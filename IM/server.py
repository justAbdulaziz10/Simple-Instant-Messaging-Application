import socket
import threading
import json
import time
import logging
import hashlib
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server_log.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("IM-Server")

class IMServer:
    def __init__(self, host='127.0.0.1', port=8888):
        """Initialize the IM server with host, port and necessary data structures"""
        self.host = host
        self.port = port
        self.server_socket = None
        
        # Dictionary to store active clients: {username: (socket, address)}
        self.clients = {}
        
        # Dictionary to store user credentials: {username: hashed_password}
        self.user_credentials = {
            "alice": self._hash_password("alice123"),
            "bob": self._hash_password("bob123"),
            "charlie": self._hash_password("charlie123")
        }
        
        # Dictionary to store chat history: {username: [messages]}
        self.chat_history = {}
        
        # Lock to protect shared resources
        self.lock = threading.RLock()
        
        # Flag to control server shutdown
        self.running = False

    def _hash_password(self, password):
        """Hash a password for secure storage"""
        return hashlib.sha256(password.encode()).hexdigest()

    def start(self):
        """Start the server and listen for connections"""
        try:
            # Create a socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Allow reuse of address
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind the socket to the specified host and port
            self.server_socket.bind((self.host, self.port))
            
            # Listen for connections (max 10 queued connections)
            self.server_socket.listen(10)
            
            self.running = True
            logger.info(f"Server started on {self.host}:{self.port}")
            
            # Accept client connections in a loop
            while self.running:
                try:
                    # Accept a connection
                    client_socket, address = self.server_socket.accept()
                    logger.info(f"New connection from {address}")
                    
                    # Handle the client in a new thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:  # Only log errors if server is still running
                        logger.error(f"Error accepting connection: {e}")
            
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.shutdown()

    def handle_client(self, client_socket, address):
        """Handle a client connection in a separate thread"""
        username = None
        
        try:
            # First, authenticate the client
            logger.info(f"Waiting for authentication from {address}")
            auth_message = self._receive_message(client_socket)
            
            if auth_message and auth_message.get('type') == 'login':
                username = auth_message.get('username')
                password = auth_message.get('password')
                
                logger.info(f"Login attempt from user: {username}")
                
                if self._authenticate_user(username, password):
                    # Successful authentication
                    logger.info(f"Authentication successful for {username}")
                    
                    with self.lock:
                        # Check if user is already logged in
                        if username in self.clients:
                            logger.info(f"User {username} already logged in, refusing connection")
                            response = {'type': 'login_response', 'status': 'failed', 'message': 'User already logged in'}
                            self._send_message(client_socket, response)
                            client_socket.close()
                            return
                        
                        # Add the client to active clients
                        self.clients[username] = client_socket
                        
                        # Initialize chat history if needed
                        if username not in self.chat_history:
                            self.chat_history[username] = []
                    
                    # Send successful login response
                    logger.info(f"Sending successful login response to {username}")
                    response = {'type': 'login_response', 'status': 'success', 'message': 'Authentication successful'}
                    self._send_message(client_socket, response)
                    
                    # Broadcast user online status
                    self._broadcast_user_status(username, "online")
                    
                    # Process messages from the client
                    self._process_client_messages(username, client_socket)
                else:
                    # Failed authentication
                    logger.info(f"Authentication failed for {username}")
                    response = {'type': 'login_response', 'status': 'failed', 'message': 'Invalid username or password'}
                    self._send_message(client_socket, response)
            else:
                # Invalid login attempt
                logger.warning(f"Invalid login attempt from {address}")
                response = {'type': 'error', 'message': 'Authentication required'}
                self._send_message(client_socket, response)
        
        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        finally:
            # Clean up when client disconnects
            if username and username in self.clients:
                with self.lock:
                    del self.clients[username]
                
                # Broadcast user offline status
                self._broadcast_user_status(username, "offline")
                
                logger.info(f"Client {username} disconnected")
            
            try:
                client_socket.close()
            except:
                pass

    def _process_client_messages(self, username, client_socket):
        """Process messages from a connected client"""
        while True:
            try:
                # Receive a message
                message = self._receive_message(client_socket)
                
                if not message:
                    break
                
                # Add timestamp if not present
                if 'timestamp' not in message:
                    message['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S")
                
                # Ensure sender is set correctly
                message['sender'] = username
                
                # Log the message
                logger.info(f"Message from {username}: {message['type']}")
                
                # Process the message based on its type
                if message['type'] == 'unicast':
                    self._handle_unicast(message)
                elif message['type'] == 'multicast':
                    self._handle_multicast(message)
                elif message['type'] == 'broadcast':
                    self._handle_broadcast(message)
                elif message['type'] == 'get_users':
                    self._handle_get_users(username)
                elif message['type'] == 'logout':
                    break
                else:
                    response = {'type': 'error', 'message': 'Unknown message type'}
                    self._send_message(client_socket, response)
                
            except Exception as e:
                logger.error(f"Error processing message from {username}: {e}")
                break

    def _handle_unicast(self, message):
        """Handle a unicast (direct) message"""
        recipient = message.get('recipient')
        
        if not recipient:
            return
        
        # Remove any angle brackets if present
        recipient = recipient.strip('<>')
        
        with self.lock:
            # Check if recipient is connected
            if recipient in self.clients:
                recipient_socket = self.clients[recipient]
                
                # Send the message to the recipient
                try:
                    self._send_message(recipient_socket, message)
                    
                    # Store in chat history
                    if recipient not in self.chat_history:
                        self.chat_history[recipient] = []
                    self.chat_history[recipient].append(message)
                    
                    # Store in sender's history as well
                    sender = message.get('sender')
                    if sender and sender in self.chat_history:
                        self.chat_history[sender].append(message)
                    
                except Exception as e:
                    logger.error(f"Error sending unicast message to {recipient}: {e}")
            else:
                # Recipient is not online, send error to sender
                error_msg = {
                    'type': 'error',
                    'message': f"User '{recipient}' is not online",
                    'original_message': message
                }
                
                try:
                    sender = message.get('sender')
                    if sender and sender in self.clients:
                        self._send_message(self.clients[sender], error_msg)
                except Exception as e:
                    logger.error(f"Error sending error message to {message.get('sender')}: {e}")

    def _handle_multicast(self, message):
        """Handle a multicast message (to multiple specific recipients)"""
        recipients = message.get('recipients', [])
        
        if not recipients or not isinstance(recipients, list):
            return
        
        # Keep track of unreachable recipients
        unreachable = []
        
        with self.lock:
            for recipient in recipients:
                if recipient in self.clients:
                    try:
                        # Send message to this recipient
                        self._send_message(self.clients[recipient], message)
                        
                        # Store in recipient's history
                        if recipient not in self.chat_history:
                            self.chat_history[recipient] = []
                        self.chat_history[recipient].append(message)
                    except Exception as e:
                        logger.error(f"Error sending multicast message to {recipient}: {e}")
                        unreachable.append(recipient)
                else:
                    unreachable.append(recipient)
            
            # Store in sender's history
            sender = message.get('sender')
            if sender and sender in self.chat_history:
                self.chat_history[sender].append(message)
        
        # If there were unreachable recipients, inform the sender
        if unreachable and sender and sender in self.clients:
            error_msg = {
                'type': 'error',
                'message': f"Could not deliver message to: {', '.join(unreachable)}",
                'original_message': message
            }
            
            try:
                self._send_message(self.clients[sender], error_msg)
            except Exception as e:
                logger.error(f"Error sending error message to {sender}: {e}")

    def _handle_broadcast(self, message):
        """Handle a broadcast message (to all users)"""
        sender = message.get('sender')
        
        with self.lock:
            # Send to all clients except the sender
            for username, client_socket in self.clients.items():
                if username != sender:
                    try:
                        self._send_message(client_socket, message)
                        
                        # Store in recipient's history
                        if username not in self.chat_history:
                            self.chat_history[username] = []
                        self.chat_history[username].append(message)
                    except Exception as e:
                        logger.error(f"Error broadcasting to {username}: {e}")
            
            # Store in sender's history
            if sender and sender in self.chat_history:
                self.chat_history[sender].append(message)

    def _handle_get_users(self, username):
        """Handle a request to get the list of online users"""
        with self.lock:
            online_users = list(self.clients.keys())
        
        response = {
            'type': 'user_list',
            'users': online_users
        }
        
        try:
            if username in self.clients:
                self._send_message(self.clients[username], response)
        except Exception as e:
            logger.error(f"Error sending user list to {username}: {e}")

    def _broadcast_user_status(self, username, status):
        """Broadcast a user's status (online/offline) to all clients"""
        status_msg = {
            'type': 'user_status',
            'username': username,
            'status': status,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        with self.lock:
            for client_username, client_socket in self.clients.items():
                if client_username != username:  # Don't send to the user themselves
                    try:
                        self._send_message(client_socket, status_msg)
                    except Exception as e:
                        logger.error(f"Error broadcasting status to {client_username}: {e}")

    def _authenticate_user(self, username, password):
        """Authenticate a user based on username and password"""
        if not username or not password:
            return False
        
        # Hash the provided password
        hashed_password = self._hash_password(password)
        
        # Check if credentials match
        return (username in self.user_credentials and 
                self.user_credentials[username] == hashed_password)

    def _send_message(self, sock, message):
        """Send a message to a socket"""
        try:
            # Convert the message to JSON and encode as bytes
            json_data = json.dumps(message).encode('utf-8')
            
            # Send the message length as a 4-byte integer
            message_length = len(json_data)
            sock.sendall(message_length.to_bytes(4, byteorder='big'))
            
            # Send the actual message
            sock.sendall(json_data)
            logger.info(f"Sent message: {message.get('type', 'unknown type')}")
            return True
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            return False  # Return False instead of raising exception

    def _receive_message(self, sock):
        """Receive a message from a socket"""
        try:
            # Receive the message length (4 bytes)
            length_bytes = sock.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                return None
            
            # Convert bytes to integer
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive the message data
            buffer = bytearray()
            while len(buffer) < message_length:
                chunk = sock.recv(min(message_length - len(buffer), 4096))
                if not chunk:
                    return None
                buffer.extend(chunk)
            
            # Decode and parse the JSON message
            json_data = buffer.decode('utf-8')
            message = json.loads(json_data)
            logger.info(f"Received message: {message.get('type', 'unknown type')}")
            return message
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            return None  # Return None instead of raising exception

    def shutdown(self):
        """Shut down the server gracefully"""
        self.running = False
        logger.info("Shutting down server...")
        
        # Close all client connections
        with self.lock:
            for username, client_socket in self.clients.items():
                try:
                    client_socket.close()
                except Exception as e:
                    logger.error(f"Error closing client socket: {e}")
            
            self.clients.clear()
        
        # Close the server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                logger.error(f"Error closing server socket: {e}")
            
            self.server_socket = None
        
        logger.info("Server shutdown complete")


if __name__ == "__main__":
    # Create and start the server
    server = IMServer()
    
    try:
        print("Starting IM Server. Press Ctrl+C to shut down.")
        server.start()
    except KeyboardInterrupt:
        print("Server shutdown requested.")
    finally:
        server.shutdown()