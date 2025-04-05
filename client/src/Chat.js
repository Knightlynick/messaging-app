import React, { useEffect, useState, useRef } from 'react';
import './App.css';

function Chat() {
  const [username, setUsername] = useState("");
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);
  const [connected, setConnected] = useState(false);
  const [joined, setJoined] = useState(false);
  const socketRef = useRef(null);
  const messagesEndRef = useRef(null);

  // Auto-scroll to bottom when messages update
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  // Connect to WebSocket server
  useEffect(() => {
    const socket = new WebSocket('ws://127.0.0.1:12345');
    socketRef.current = socket;

    socket.onopen = () => {
      setConnected(true);
      setMessages((prev) => [...prev, { type: 'system', content: 'Connected to the server' }]);
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setMessages((prev) => [...prev, data]);
      } catch (e) {
        setMessages((prev) => [...prev, { type: 'system', content: event.data }]);
      }
    };

    socket.onerror = (error) => {
      console.error("WebSocket error:", error);
      setMessages((prev) => [...prev, { type: 'error', content: 'WebSocket error' }]);
    };

    socket.onclose = () => {
      setConnected(false);
      setJoined(false);
      setMessages((prev) => [...prev, { type: 'system', content: 'Disconnected from the server' }]);
    };

    return () => {
      socket.close();
    };
  }, []);

  // Join the chat with username
  const joinChat = () => {
    if (username.trim() && socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      const joinMsg = { type: 'join', username: username.trim() };
      socketRef.current.send(JSON.stringify(joinMsg));
      setJoined(true);
    }
  };

  // Send a chat message
  const sendMessage = () => {
    if (message.trim() && socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      const chatMsg = { type: 'chat', content: message.trim(), username };
      socketRef.current.send(JSON.stringify(chatMsg));
      setMessage("");
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      if (!joined) {
        joinChat();
      } else {
        sendMessage();
      }
    }
  };

  const renderMessage = (msg, index) => {
    if (typeof msg === 'string') {
      return <div key={index} className="message">{msg}</div>;
    }
    switch (msg.type) {
      case 'system':
        return (
          <div key={index} className="message system-message">
            <span className="system-indicator">SYSTEM:</span> {msg.content}
          </div>
        );
      case 'error':
        return (
          <div key={index} className="message error-message">
            <span className="error-indicator">ERROR:</span> {msg.content}
          </div>
        );
      case 'chat':
        return (
          <div key={index} className="message chat-message">
            <span className="username">{msg.username}:</span> {msg.content}
          </div>
        );
      default:
        return <div key={index} className="message">{JSON.stringify(msg)}</div>;
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Global Chat Room</h1>
        <div className="connection-status">Status: {connected ? 'Connected' : 'Disconnected'}</div>
      </header>
      
      <div className="messages-container">
        <div className="messages">
          {messages.map((msg, index) => renderMessage(msg, index))}
          <div ref={messagesEndRef} />
        </div>
      </div>
      
      {!joined ? (
        <div className="join-container">
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Enter your username..."
            disabled={!connected}
            className="username-input"
          />
          <button 
            onClick={joinChat} 
            disabled={!connected || !username.trim()}
            className="join-button"
          >
            Join Chat
          </button>
        </div>
      ) : (
        <div className="input-area">
          <input
            type="text"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Type a message..."
            disabled={!connected}
            className="message-input"
          />
          <button 
            onClick={sendMessage} 
            disabled={!connected || !message.trim()}
            className="send-button"
          >
            Send
          </button>
        </div>
      )}
    </div>
  );
}

export default Chat;
