import React, { useEffect, useState, useRef } from 'react';
import './App.css';

function Chat({ onLogout }) {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);
  const [connected, setConnected] = useState(false);
  const socketRef = useRef(null);
  const messagesEndRef = useRef(null);
  const username = localStorage.getItem('username') || "Anonymous";

  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  useEffect(() => {
    const socket = new WebSocket('ws://localhost:12345');
    socketRef.current = socket;
  
    socket.onopen = () => {
      console.log("WebSocket connected");
      setConnected(true);
      const username = localStorage.getItem("username") || "Anonymous";
      // Only send the join message when the connection is fully open.
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "join", username }));
      }
      setMessages(prev => [...prev, { type: 'system', content: 'Connected to the server' }]);
    };
  
    socket.onmessage = (event) => {
      console.log("WebSocket message received", event.data);
      try {
        const data = JSON.parse(event.data);
        setMessages(prev => [...prev, data]);
      } catch (e) {
        setMessages(prev => [...prev, { type: 'system', content: event.data }]);
      }
    };
  
    socket.onerror = (error) => {
      console.error("WebSocket error:", error);
      setMessages(prev => [...prev, { type: 'error', content: 'WebSocket error' }]);
    };
  
    socket.onclose = () => {
      console.log("WebSocket closed");
      setConnected(false);
      setMessages(prev => [...prev, { type: 'system', content: 'Disconnected from the server' }]);
    };
  
    return () => {
      // Make sure the socket is open before closing.
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close();
      }
    };
  }, []);
  

  const sendMessage = () => {
    if (message.trim() && socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      const chatMsg = { type: 'chat', content: message.trim(), username };
      socketRef.current.send(JSON.stringify(chatMsg));
      setMessage("");
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      sendMessage();
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

  const handleLogout = () => {
    if (socketRef.current) {
      socketRef.current.close();
    }
    onLogout();
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>Global Chat Room</h1>
        <div className="connection-status">
          Status: {connected ? 'Connected' : 'Disconnected'}
          <button onClick={handleLogout} className="logout-button">Logout</button>
        </div>
      </header>
      
      <div className="messages-container">
        <div className="messages">
          {messages.map((msg, index) => renderMessage(msg, index))}
          <div ref={messagesEndRef} />
        </div>
      </div>
      
      <div className="input-area">
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyDown={handleKeyPress}
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
    </div>
  );
}

export default Chat;