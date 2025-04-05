import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';

function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const navigate = useNavigate();

  const handleRegister = (e) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      alert("Passwords do not match!");
      return;
    }
    console.log("Registering:", username, password);
    // Registration logic placeholder, then redirect to login page
    navigate('/login');
  };

  return (
    <div style={containerStyle}>
      <header style={headerStyle}>
        <h1>Messaging App</h1>
      </header>
      <div style={formContainerStyle}>
        <h2 style={titleStyle}>Register</h2>
        <form onSubmit={handleRegister} style={formStyle}>
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
          <label>
            Confirm Password:
            <input 
              type="password" 
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              style={inputStyle}
            />
          </label>
          <button type="submit" style={buttonStyle}>Register</button>
        </form>
        <p style={{ textAlign: 'center' }}>
          Already have an account? <Link to="/login">Login here</Link>.
        </p>
      </div>
    </div>
  );
}

export default Register;

/* Inline styles */
const containerStyle = {
  maxWidth: '800px',
  margin: '0 auto',
  padding: '20px',
  boxSizing: 'border-box',
  fontFamily: "Arial, sans-serif"
};

const headerStyle = {
  backgroundColor: '#282c34',
  color: 'white',
  padding: '20px',
  display: 'flex',
  justifyContent: 'center',
  alignItems: 'center'
};

const formContainerStyle = {
  maxWidth: '400px',
  margin: '20px auto',
  padding: '20px',
  backgroundColor: '#f5f5f5',
  borderRadius: '8px'
};

const titleStyle = {
  textAlign: 'center',
  marginBottom: '20px'
};

const formStyle = {
  display: 'flex',
  flexDirection: 'column'
};

const inputStyle = {
  padding: '10px',
  marginBottom: '10px',
  border: '1px solid #ccc',
  borderRadius: '4px',
  fontSize: '16px'
};

const buttonStyle = {
  padding: '10px 20px',
  backgroundColor: '#4caf50',
  color: 'white',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontSize: '16px'
};
