/*
Login.js
This file implements the login form and sends an HTTP request to the /auth endpoint to authenticate users. It updates local storage and the app state based on the response
*/
import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'

function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const navigate = useNavigate()

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      const response = await fetch('http://localhost:8080/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          type: 'auth',
          action: 'login',
          username,
          password
        }),
        credentials: 'include'
      })
      
      const data = await response.json()
      if (data.status === 'success') {
        onLogin(`${username}:${Date.now()}`)
        navigate('/chat')
      } else {
        setError(data.message || 'Login failed. Please try again')
      }
    } catch (err) {
      setError('Connection error. Please try again later')
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
        <h2 style={titleStyle}>Login</h2>
        {error && <div style={errorStyle}>{error}</div>}
        <form onSubmit={handleLogin} style={formStyle}>
          <label style={labelStyle}>
            Username:
            <input 
              type="text" 
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
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
              style={inputStyle}
            />
          </label>
          <button 
            type="submit" 
            style={buttonStyle}
            disabled={isLoading}
          >
            {isLoading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        <p style={{ textAlign: 'center', marginTop: '20px' }}>
          Don't have an account? <Link to="/register" style={linkStyle}>Register here</Link>
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

const linkStyle = {
  color: '#4caf50',
  textDecoration: 'none',
  fontWeight: 'bold'
}

export default Login
