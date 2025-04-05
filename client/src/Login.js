import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:12345/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (response.ok) {
        onLogin(); // Mark the user as authenticated.
        navigate('/chat'); // Redirect to chat page.
      } else {
        alert(data.message || 'Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      alert('Login error');
    }
  };

  return (
    <div style={containerStyle}>
      <header style={headerStyle}>
        <h1>Messaging App</h1>
      </header>
      <div style={formContainerStyle}>
        <h2 style={titleStyle}>Login</h2>
        <form onSubmit={handleLogin} style={formStyle}>
          <label>
            Username:
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              style={inputStyle}
            />
          </label>
          <label>
            Password:
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={inputStyle}
            />
          </label>
          <button type="submit" style={buttonStyle}>Login</button>
        </form>
        <p style={{ textAlign: 'center' }}>
          Don't have an account? <Link to="/register">Register here</Link>.
        </p>
      </div>
    </div>
  );
}

export default Login;

/* Inline styles */
const containerStyle = {
  maxWidth: '800px',
  margin: '0 auto',
  padding: '20px',
  boxSizing: 'border-box',
  fontFamily: "Arial, sans-serif",
};

const headerStyle = {
  backgroundColor: '#282c34',
  color: 'white',
  padding: '20px',
  display: 'flex',
  justifyContent: 'center',
  alignItems: 'center',
};

const formContainerStyle = {
  maxWidth: '400px',
  margin: '20px auto',
  padding: '20px',
  backgroundColor: '#f5f5f5',
  borderRadius: '8px',
};

const titleStyle = {
  textAlign: 'center',
  marginBottom: '20px',
};

const formStyle = {
  display: 'flex',
  flexDirection: 'column',
};

const inputStyle = {
  padding: '10px',
  marginBottom: '10px',
  border: '1px solid #ccc',
  borderRadius: '4px',
  fontSize: '16px',
};

const buttonStyle = {
  padding: '10px 20px',
  backgroundColor: '#4caf50',
  color: 'white',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontSize: '16px',
};
