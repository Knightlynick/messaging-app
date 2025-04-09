/*
Register.js
This file implements the registration form for new users. It validates input, sends a request to register a new user, and displays success or error messages
*/
import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { API_BASE_URL } from './config'

function Register() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const navigate = useNavigate()

  const handleRegister = async (e) => {
    e.preventDefault()
    setError('')
    
    if (password !== confirmPassword) {
      setError("Passwords do not match!")
      return
    }

    if (password.length < 6) {
      setError("Password must be at least 6 characters long")
      return
    }

    setIsLoading(true)
    try {
      const response = await fetch(`${API_BASE_URL}/auth`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          type: 'auth',
          action: 'register',
          username,
          password
        }),
        credentials: 'include'
      })
      
      const data = await response.json()
      if (data.status === 'success') {
        setSuccess(true)
        setTimeout(() => navigate('/login'), 2000)
      } else {
        setError(data.message || 'Registration failed. Please try again!')
      }
    } catch (err) {
      setError('Connection error. Please try again later!')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div style={containerStyle}>
      <header style={headerStyle}>
        <h1>Messaging App</h1>
      </header>
      <div style={formContainerStyle}>
        <h2 style={titleStyle}>Register</h2>
        {error && <div style={errorStyle}>{error}</div>}
        {success && <div style={successStyle}>Registration successful! Redirecting to login...</div>}
        <form onSubmit={handleRegister} style={formStyle}>
          <label style={labelStyle}>
            Username:
            <input 
              type="text" 
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              minLength="3"
              style={inputStyle}
            />
          </label>
          <label style={labelStyle}>
            Password:
            <input 
              type="password" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength="6"
              style={inputStyle}
            />
          </label>
          <label style={labelStyle}>
            Confirm Password:
            <input 
              type="password" 
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              style={inputStyle}
            />
          </label>
          <button 
            type="submit" 
            style={buttonStyle}
            disabled={isLoading}
          >
            {isLoading ? 'Registering...' : 'Register'}
          </button>
        </form>
        <p style={{ textAlign: 'center', marginTop: '20px' }}>
          Already have an account? <Link to="/login" style={linkStyle}>Login here</Link>
        </p>
      </div>
    </div>
  )
}

const containerStyle = {
  maxWidth: '800px',
  margin: '0 auto',
  padding: '20px',
  boxSizing: 'border-box',
  fontFamily: "Arial, sans-serif"
}

const headerStyle = {
  backgroundColor: '#282c34',
  color: 'white',
  padding: '20px',
  display: 'flex',
  justifyContent: 'center',
  alignItems: 'center',
  borderRadius: '8px 8px 0 0',
  marginBottom: '20px'
}

const formContainerStyle = {
  maxWidth: '400px',
  margin: '0 auto',
  padding: '30px',
  backgroundColor: '#f5f5f5',
  borderRadius: '8px',
  boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
}

const titleStyle = {
  textAlign: 'center',
  marginBottom: '20px',
  color: '#333'
}

const formStyle = {
  display: 'flex',
  flexDirection: 'column'
}

const labelStyle = {
  marginBottom: '15px',
  display: 'flex',
  flexDirection: 'column',
  fontSize: '14px',
  color: '#555'
}

const inputStyle = {
  padding: '12px',
  marginTop: '5px',
  border: '1px solid #ddd',
  borderRadius: '4px',
  fontSize: '16px',
  outline: 'none',
  transition: 'border 0.3s'
}

const buttonStyle = {
  padding: '12px 20px',
  backgroundColor: '#4caf50',
  color: 'white',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontSize: '16px',
  marginTop: '10px',
  transition: 'background-color 0.3s'
}

const errorStyle = {
  color: '#d32f2f',
  marginBottom: '15px',
  textAlign: 'center',
  padding: '10px',
  backgroundColor: '#ffebee',
  borderRadius: '4px'
}

const successStyle = {
  color: '#388e3c',
  marginBottom: '15px',
  textAlign: 'center',
  padding: '10px',
  backgroundColor: '#e8f5e9',
  borderRadius: '4px'
}

const linkStyle = {
  color: '#4caf50',
  textDecoration: 'none',
  fontWeight: 'bold'
}

export default Register
