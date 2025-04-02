import socket
import threading
import json
import time
import os
import sys
import logging
import base64
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client_log.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("IM-Client")

class IMClient:
    def __init__(self, host='127.0.0.1', port=8888):
        """Initialize the IM client with server host and port"""
        self.host = host
        self.port = port
        self.socket = None
        self.username = None
        self.running = False
        self.receiver_thread = None
        
        # Encryption settings
        self.encryption_key = None
        self.cipher = None
        self.encryption_enabled = True
        
        # Event to signal successful login
        self.login_event = threading.Event()
        
        # Callback for message handling
        self.message_callback = None

    def connect(self):
        """Connect to the IM server"""
        try:
            # Create a socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to the server
            self.socket.connect((self.host, self.port))
            
            logger.info(f"Connected to server at {self.host}:{self.port}")
            return True
        
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def login(self, username, password):
        """Log in to the IM server with username and password"""
        if not self.socket:
            logger.error("Not connected to server")
            return False
        
        try:
            # Clear login event before starting
            self.login_event.clear()
            
            # Prepare login message
            login_message = {
                'type': 'login',
                'username': username,
                'password': password
            }
            
            # Start the message receiver thread first
            self.running = True
            self.receiver_thread = threading.Thread(target=self._receive_messages, daemon=True)
            self.receiver_thread.start()
            
            # Send login message
            logger.info(f"Sending login request for user: {username}")
            if not self._send_message(login_message):
                logger.error("Failed to send login message")
                self.running = False
                return False
            
            # Wait for response (timeout after 10 seconds)
            if not self.login_event.wait(10):
                logger.error("Login timeout")
                self.running = False
                return False
            
            # If we get here, login was successful
            self.username = username
            logger.info(f"Successfully logged in as {username}")
            return True
        
        except Exception as e:
            logger.error(f"Login error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.running = False
            return False

    def logout(self):
        """Log out from the IM server"""
        if self.socket and self.running:
            try:
                # Send logout message
                logout_message = {
                    'type': 'logout',
                    'sender': self.username
                }
                self._send_message(logout_message)
            except Exception as e:
                logger.error(f"Error sending logout message: {e}")
            
            # Stop the receiver thread
            self.running = False
            
            # Close the socket
            try:
                self.socket.close()
            except Exception as e:
                logger.error(f"Error closing socket: {e}")
            
            self.socket = None
            logger.info("Logged out and disconnected from server")

    def send_unicast(self, recipient, content):
        """Send a direct message to a single user"""
        if not self.socket or not self.running:
            logger.error("Not connected or logged in")
            return False
        
        try:
            message = {
                'type': 'unicast',
                'sender': self.username,
                'recipient': recipient,
                'content': content,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Let the server handle encryption - this keeps the code simpler
            # as the server knows which keys to use for each recipient
            
            self._send_message(message)
            return True
        
        except Exception as e:
            logger.error(f"Error sending unicast message: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def send_multicast(self, recipients, content):
        """Send a message to multiple specific users"""
        if not self.socket or not self.running:
            logger.error("Not connected or logged in")
            return False
        
        if not isinstance(recipients, list) or not recipients:
            logger.error("Recipients must be a non-empty list")
            return False
        
        try:
            message = {
                'type': 'multicast',
                'sender': self.username,
                'recipients': recipients,
                'content': content,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self._send_message(message)
            return True
        
        except Exception as e:
            logger.error(f"Error sending multicast message: {e}")
            return False

    def send_broadcast(self, content):
        """Send a message to all users"""
        if not self.socket or not self.running:
            logger.error("Not connected or logged in")
            return False
        
        try:
            message = {
                'type': 'broadcast',
                'sender': self.username,
                'content': content,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self._send_message(message)
            return True
        
        except Exception as e:
            logger.error(f"Error sending broadcast message: {e}")
            return False

    def get_online_users(self):
        """Request a list of online users from the server"""
        if not self.socket or not self.running:
            logger.error("Not connected or logged in")
            return False
        
        try:
            message = {
                'type': 'get_users',
                'sender': self.username
            }
            
            self._send_message(message)
            return True
        
        except Exception as e:
            logger.error(f"Error requesting user list: {e}")
            return False

    def set_message_callback(self, callback):
        """Set a callback function to handle incoming messages"""
        self.message_callback = callback

    def _send_message(self, message):
        """Send a message to the server"""
        try:
            # Convert the message to JSON and encode as bytes
            json_data = json.dumps(message).encode('utf-8')
            
            # Send the message length as a 4-byte integer
            message_length = len(json_data)
            self.socket.sendall(message_length.to_bytes(4, byteorder='big'))
            
            # Send the actual message
            self.socket.sendall(json_data)
            logger.info(f"Sent message: {message.get('type', 'unknown')}")
            return True
        
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def _receive_message(self):
        """Receive a message from the server"""
        try:
            # Receive the message length (4 bytes)
            length_bytes = self.socket.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                return None
            
            # Convert bytes to integer
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive the message data
            buffer = bytearray()
            while len(buffer) < message_length:
                chunk = self.socket.recv(min(message_length - len(buffer), 4096))
                if not chunk:
                    return None
                buffer.extend(chunk)
            
            # Decode and parse the JSON message
            json_data = buffer.decode('utf-8')
            message = json.loads(json_data)
            logger.info(f"Received message: {message.get('type', 'unknown')}")
            return message
        
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

    def _receive_messages(self):
        """Continuously receive and process messages from the server"""
        while self.running:
            try:
                message = self._receive_message()
                
                if not message:
                    # If we received None, the connection is likely closed
                    logger.warning("Lost connection to server")
                    self.running = False
                    break
                
                # Process the message based on its type
                if message.get('type') == 'login_response':
                    self._handle_login_response(message)
                elif self.message_callback:
                    # Pass other messages to the callback
                    self.message_callback(message)
            
            except Exception as e:
                if self.running:  # Only log errors if we're still supposed to be running
                    logger.error(f"Error in message receiver: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                
                break
        
        logger.info("Message receiver stopped")

    def _handle_login_response(self, message):
        """Handle the response to a login attempt"""
        status = message.get('status')
        
        if status == 'success':
            logger.info("Login successful")
            
            # If the server provided an encryption key, store it
            if 'encryption_key' in message:
                try:
                    encryption_key = message.get('encryption_key')
                    if isinstance(encryption_key, str):
                        encryption_key = encryption_key.encode('utf-8')
                    
                    self.encryption_key = encryption_key
                    self.cipher = Fernet(self.encryption_key)
                    logger.info("Encryption enabled with server-provided key")
                except Exception as e:
                    logger.error(f"Error setting up encryption: {e}")
                    self.encryption_enabled = False
            
            # Set the login event to unblock the login method
            self.login_event.set()
        else:
            logger.error(f"Login failed: {message.get('message', 'Unknown error')}")
            # Don't set the event, so login will timeout


class IMClientCLI:
    def __init__(self, host='127.0.0.1', port=8888):
        """Initialize the CLI client with the IM client"""
        self.client = IMClient(host, port)
        self.client.set_message_callback(self._handle_message)
        self.running = False

    def start(self):
        """Start the CLI client"""
        print("=== Simple Instant Messaging Client ===")
        print("Connecting to server...")
        
        if not self.client.connect():
            print("Failed to connect to server.")
            return
        
        # Authenticate the user
        if not self._authenticate():
            print("Authentication failed. Exiting.")
            return
        
        print(f"Welcome, {self.client.username}!")
        print("Type /help for available commands.")
        
        self.running = True
        
        # Start the CLI input loop
        try:
            self._input_loop()
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            self.client.logout()

    def _authenticate(self):
        """Authenticate the user with the server"""
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            username = input("Enter username: ")
            password = input("Enter password: ")  # In a real app, use getpass
            
            print("Logging in...")
            if self.client.login(username, password):
                return True
            
            attempts += 1
            print(f"Login failed. {max_attempts - attempts} attempts remaining.")
        
        return False

    def _input_loop(self):
        """Process user input in a loop"""
        while self.running:
            try:
                user_input = input("\n> ")
                
                if not user_input:
                    continue
                
                # Process commands
                if user_input.startswith('/'):
                    self._process_command(user_input)
                else:
                    # Default to broadcast if no command is specified
                    print("Use /broadcast <message> to send a message to everyone.")
                    print("Or type /help to see all available commands.")
            
            except Exception as e:
                print(f"Error: {e}")
                import traceback
                logger.error(traceback.format_exc())

    def _process_command(self, command):
        """Process a command entered by the user"""
        parts = command.split(' ', 1)
        cmd = parts[0].lower()
        
        if cmd == '/help':
            self._show_help()
        
        elif cmd == '/quit' or cmd == '/exit':
            print("Logging out...")
            self.running = False
        
        elif cmd == '/users':
            print("Requesting user list...")
            self.client.get_online_users()
        
        elif cmd == '/msg' or cmd == '/unicast':
            if len(parts) < 2:
                print("Usage: /msg <username> <message>")
                return
            
            msg_parts = parts[1].split(' ', 1)
            if len(msg_parts) < 2:
                print("Usage: /msg <username> <message>")
                return
            
            recipient = msg_parts[0].strip()
            # Remove any brackets if present
            recipient = recipient.strip('<>')
            content = msg_parts[1]
            
            if self.client.send_unicast(recipient, content):
                print(f"Message sent to {recipient}")
        
        elif cmd == '/group' or cmd == '/multicast':
            if len(parts) < 2:
                print("Usage: /group <username1,username2,...> <message>")
                return
            
            msg_parts = parts[1].split(' ', 1)
            if len(msg_parts) < 2:
                print("Usage: /group <username1,username2,...> <message>")
                return
            
            recipients_str = msg_parts[0].strip()
            # Remove any brackets if present
            recipients_str = recipients_str.strip('<>')
            content = msg_parts[1]
            
            recipients = [r.strip() for r in recipients_str.split(',') if r.strip()]
            
            if not recipients:
                print("Please specify at least one recipient")
                return
            
            if self.client.send_multicast(recipients, content):
                print(f"Message sent to group: {', '.join(recipients)}")
        
        elif cmd == '/all' or cmd == '/broadcast':
            if len(parts) < 2:
                print("Usage: /all <message>")
                return
            
            content = parts[1]
            
            if self.client.send_broadcast(content):
                print("Broadcast message sent")
        
        else:
            print(f"Unknown command: {cmd}")
            print("Type /help for available commands")

    def _show_help(self):
        """Show help information"""
        print("\n=== Available Commands ===")
        print("/msg <username> <message>           - Send a private message to a specific user")
        print("/group <user1,user2> <message>      - Send a message to a group of users")
        print("/all <message>                      - Send a message to all users")
        print("/users                              - Show online users")
        print("/help                               - Show this help message")
        print("/quit, /exit                        - Exit the application")
        print("\nAlternative command formats:")
        print("/unicast can be used instead of /msg")
        print("/multicast can be used instead of /group")
        print("/broadcast can be used instead of /all")

    def _handle_message(self, message):
        """Handle incoming messages from the server"""
        msg_type = message.get('type', '')
        
        # Check if the message is encrypted and we have a cipher
        if message.get('encrypted') and self.cipher and 'content' in message:
            try:
                # Decrypt the message content
                encrypted_content = message.get('content', '')
                if isinstance(encrypted_content, str):
                    encrypted_content = encrypted_content.encode('utf-8')
                
                decrypted_content = self.cipher.decrypt(encrypted_content).decode('utf-8')
                
                # Replace the encrypted content with decrypted content
                message['content'] = decrypted_content
                message['encrypted'] = False
            except Exception as e:
                logger.error(f"Error decrypting message: {e}")
                # If decryption fails, we'll display the message as is
        
        if msg_type == 'unicast':
            sender = message.get('sender', 'Unknown')
            content = message.get('content', '')
            timestamp = message.get('timestamp', '')
            print(f"\n[{timestamp}] {sender} (private): {content}")
        
        elif msg_type == 'multicast':
            sender = message.get('sender', 'Unknown')
            content = message.get('content', '')
            timestamp = message.get('timestamp', '')
            recipients = message.get('recipients', [])
            if self.client.username in recipients:
                print(f"\n[{timestamp}] {sender} (group): {content}")
        
        elif msg_type == 'broadcast':
            sender = message.get('sender', 'Unknown')
            content = message.get('content', '')
            timestamp = message.get('timestamp', '')
            print(f"\n[{timestamp}] {sender} (broadcast): {content}")
        
        elif msg_type == 'user_status':
            username = message.get('username', '')
            status = message.get('status', '')
            print(f"\n--- User {username} is now {status} ---")
        
        elif msg_type == 'user_list':
            users = message.get('users', [])
            print("\n=== Online Users ===")
            if users:
                for user in users:
                    print(f"- {user}")
            else:
                print("No users online")
        
        elif msg_type == 'error':
            error_msg = message.get('message', 'Unknown error')
            print(f"\nError: {error_msg}")
        
        else:
            print(f"\nReceived unknown message type: {msg_type}")
        
        # Refresh the prompt
        print("\n> ", end='', flush=True)


if __name__ == "__main__":
    # Get server host and port from command line arguments, or use defaults
    host = '127.0.0.1'
    port = 8888
    
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            port = int(sys.argv[2])
        except ValueError:
            print(f"Invalid port number: {sys.argv[2]}")
            sys.exit(1)
    
    # Create and start the CLI client
    client = IMClientCLI(host, port)
    client.start()
