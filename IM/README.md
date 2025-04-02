# Simple Instant Messaging Application

A command-line based instant messaging application with client-server architecture, supporting unicast, multicast, and broadcast messaging.

## Overview

This application consists of two main components:

1. **Server**: Manages connections, authenticates users, and routes messages between clients
2. **Client**: Connects to the server, sends messages, and receives messages from other users

The system supports three types of messaging:
- **Unicast**: One-to-one private messaging
- **Multicast**: Messaging to a specific group of users
- **Broadcast**: Messaging to all connected users

## Requirements

- Python 3.6 or higher
- No external dependencies/libraries required (uses only Python standard library)

## How to Run

### Starting the Server

1. Open a command prompt or terminal
2. Navigate to the project directory
3. Run the server using Python:

```bash
python server.py
```

By default, the server runs on localhost (127.0.0.1) port 8888. You can modify these settings in the server code if needed.

### Starting the Client

1. Open a command prompt or terminal
2. Navigate to the project directory
3. Run the client using Python:

```bash
python client.py
```

You can specify a different server address and port if the server is not running on the default location:

```bash
python client.py <server_host> <server_port>
```

Example:
```bash
python client.py 192.168.1.100 9000
```

### Using the Client

After starting the client, you'll need to:

1. Enter a username and password to log in. For testing, the following accounts are pre-configured:
   - Username: `alice`, Password: `alice123`
   - Username: `bob`, Password: `bob123`
   - Username: `charlie`, Password: `charlie123`

2. Once logged in, you can use the following commands:
   - `/msg <username> <message>` - Send a private message to a specific user
   - `/group <user1,user2,...> <message>` - Send a message to a specific group of users
   - `/all <message>` - Send a message to all connected users
   - `/users` - Show a list of online users
   - `/help` - Show available commands
   - `/quit` or `/exit` - Log out and exit the application

#### Alternative Command Syntax
- `/unicast` can be used instead of `/msg`
- `/multicast` can be used instead of `/group`
- `/broadcast` can be used instead of `/all`

## Example Usage

### Unicast (Private Message)
```
> /msg bob Hey Bob, how are you?
```

### Multicast (Group Message)
```
> /group bob,charlie Meeting at 3pm today?
```

### Broadcast (Message to Everyone)
```
> /all Hello everyone!
```

## Error Handling

The application handles various error conditions:
- Connection failures
- Authentication errors
- Messages to offline users
- Unexpected disconnections

When an error occurs, an appropriate error message will be displayed.

## Project Structure

- `server.py` - Server implementation
- `client.py` - Client implementation
- `server_log.txt` - Server log file (created when server runs)
- `client_log.txt` - Client log file (created when client runs)

## Troubleshooting

1. **Connection Refused Error**:
   - Make sure the server is running
   - Check that you're using the correct host and port

2. **Authentication Failed**:
   - Verify you're using the correct username and password

3. **Client Freezes or Disconnects**:
   - The server might have shut down, try restarting the client