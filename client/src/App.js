import React, { useEffect, useState, useRef, useCallback } from 'react';
import './App.css';

function App() {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);
  const [connected, setConnected] = useState(false);
  const [connectionError, setConnectionError] = useState("");
  const [serverAddress, setServerAddress] = useState("127.0.0.1");
  const [serverPort, setServerPort] = useState("12345");
  const [username, setUsername] = useState(`user_${Math.floor(Math.random() * 10000)}`);
  const socketRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const messagesEndRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const maxReconnectAttempts = 5;

  // Scroll to bottom of messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  // Effect to scroll to bottom when messages update
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Use useCallback to memoize the setupWebSocket function
  const setupWebSocket = useCallback(() => {
    // Clear any previous connection error
    setConnectionError("");
    
    if (socketRef.current) {
      socketRef.current.close();
    }
    // Log connection attempt
    console.log(`Attempting to connect to WebSocket server at ws://${serverAddress}:${serverPort}...`);
    
    try {
      // Create WebSocket connection
      socketRef.current = new WebSocket(`ws://${serverAddress}:${serverPort}`);
      
      // Connection opened
      socketRef.current.addEventListener('open', (event) => {
        console.log('Connected to WebSocket server');
        setConnected(true);
        setConnectionError("");
        reconnectAttemptsRef.current = 0;
        
        // Add a simple message to the chat
        setMessages((prevMessages) => [...prevMessages, "System: Connected to chat server"]);
        
        // Send a join notification after a slight delay to ensure connection is established
        setTimeout(() => {
          if (socketRef.current?.readyState === WebSocket.OPEN) {
            const joinMessage = `42["send_message","${username} has joined the chat"]`;
            socketRef.current.send(joinMessage);
          }
        }, 500);
      });
      
      // Listen for messages
      socketRef.current.addEventListener('message', (event) => {
        console.log('Received message:', event.data);
        const data = event.data;
        
        // Handle Socket.io-style messages (they start with numbers like "42")
        if (data.startsWith('42')) {
          try {
            // Extract the message content from Socket.io format
            // Format: 42["receive_message","user_1234: hello"]
            const messageStart = data.indexOf('["receive_message","') + 19;
            const messageEnd = data.lastIndexOf('"]');
            if (messageStart > 19 && messageEnd > 0) {
              const receivedMessage = data.substring(messageStart, messageEnd);
              
              // Check if it's a join/leave notification
              const isJoinLeave = 
                receivedMessage.includes("has joined") || 
                receivedMessage.includes("has left") || 
                receivedMessage.includes("client has joined") || 
                receivedMessage.includes("client has left");
              
              // Add message with notification flag if applicable
              setMessages((prevMessages) => [...prevMessages, receivedMessage]);
            }
          } catch (error) {
            console.error('Error parsing message:', error);
            setMessages((prevMessages) => [...prevMessages, "Error: Failed to parse message"]);
          }
        } else {
          console.log('Received non-standard message format:', data);
          setMessages((prevMessages) => [...prevMessages, `Raw: ${data}`]);
        }
      });
      
      // Connection error
      socketRef.current.addEventListener('error', (event) => {
        console.error('WebSocket error:', event);
        setConnectionError("Connection error. Check if the server is running.");
        setConnected(false);
      });
      
      // Connection closed
      socketRef.current.addEventListener('close', (event) => {
        console.log('Disconnected from WebSocket server. Code:', event.code, 'Reason:', event.reason);
        setConnected(false);
        
        if (!connectionError) {
          setConnectionError(`Connection closed (Code: ${event.code}). ${
            reconnectAttemptsRef.current < maxReconnectAttempts ? 'Attempting to reconnect...' : 'Max reconnect attempts reached.'
          }`);
        }
        
        // Try to reconnect with exponential backoff, but only if we haven't hit max attempts
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          clearTimeout(reconnectTimeoutRef.current);
          const backoffTime = Math.min(1000 * (2 ** reconnectAttemptsRef.current), 10000);
          reconnectAttemptsRef.current += 1;
          
          setMessages((prevMessages) => [
            ...prevMessages, 
            `System: Connection lost. Reconnect attempt ${reconnectAttemptsRef.current}/${maxReconnectAttempts} in ${backoffTime/1000} seconds...`
          ]);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            setupWebSocket();
          }, backoffTime);
        }
      });
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      setConnectionError(`Failed to create WebSocket: ${error.message}`);
    }
  }, [serverAddress, serverPort, username]); // Add username as a dependency

  useEffect(() => {
    // Initial connection
    setupWebSocket();
    
    // Clean up on unmount
    return () => {
      // Send a leave message if connected
      if (socketRef.current?.readyState === WebSocket.OPEN) {
        try {
          const leaveMessage = `42["send_message","${username} has left the chat"]`;
          socketRef.current.send(leaveMessage);
          // Small delay to ensure message is sent before closing
          setTimeout(() => socketRef.current?.close(), 300);
        } catch (error) {
          console.error('Error sending leave message:', error);
        }
      }
      
      clearTimeout(reconnectTimeoutRef.current);
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [setupWebSocket, username]); 

  const sendMessage = () => {
    if (message.trim() && socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      try {
        // Send in Socket.io format
        const socketMessage = `42["send_message","${message}"]`;
        console.log('Sending message:', socketMessage);
        socketRef.current.send(socketMessage);
        setMessage('');
      } catch (error) {
        console.error('Error sending message:', error);
        setConnectionError(`Failed to send message: ${error.message}`);
      }
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      sendMessage();
    }
  };

  const handleReconnect = () => {
    setMessages((prevMessages) => [...prevMessages, "System: Attempting to reconnect..."]);
    reconnectAttemptsRef.current = 0;
    setupWebSocket();
  };

  const updateServerConfig = () => {
    setMessages((prevMessages) => [...prevMessages, `System: Connecting to ${serverAddress}:${serverPort}...`]);
    reconnectAttemptsRef.current = 0;
    setupWebSocket();
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Messaging App</h1>
        <div className="connection-status">
          Status: {connected ? 'Connected' : 'Disconnected'}
          {connectionError && (
            <div className="error-message">
              Error: {connectionError}
              <button onClick={handleReconnect}>Reconnect</button>
            </div>
          )}
        </div>
      </header>
      
      <div className="server-config">
        <div className="server-inputs">
          <label>
            Server:
            <input 
              type="text" 
              value={serverAddress} 
              onChange={(e) => setServerAddress(e.target.value)}
              placeholder="Server address"
              disabled={connected}
            />
          </label>
          <label>
            Port:
            <input 
              type="text" 
              value={serverPort} 
              onChange={(e) => setServerPort(e.target.value)} 
              placeholder="Port number"
              disabled={connected}
            />
          </label>
          <label>
            Username:
            <input 
              type="text" 
              value={username} 
              onChange={(e) => setUsername(e.target.value)} 
              placeholder="Your username"
              disabled={connected}
            />
          </label>
        </div>
        <button onClick={updateServerConfig} disabled={connected}>
          Connect to Server
        </button>
      </div>
      
      <div className="message-container">
        {messages.length === 0 ? (
          <div className="empty-message">No messages yet</div>
        ) : (
          <>
            {messages.map((msg, index) => {
              // Check if the message is from the system
              const isSystem = msg.startsWith("System:");
              // Check if it's a user join/leave notification
              const isJoinLeave = msg.includes("has joined") || msg.includes("has left") || 
                                  msg.includes("client has joined") || msg.includes("client has left");
              
              return (
                <div key={index} className={`message ${isSystem ? 'system-message' : ''} ${isJoinLeave ? 'join-leave' : ''}`}>
                  {msg}
                </div>
              );
            })}
            <div ref={messagesEndRef} />
          </>
        )}
      </div>
      
      <div className="input-area">
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Type your message..."
          disabled={!connected}
        />
        <button onClick={sendMessage} disabled={!connected}>
          Send
        </button>
      </div>
    </div>
  );
}

export default App;