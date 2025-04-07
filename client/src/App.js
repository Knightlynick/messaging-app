/*
App.js
This file is the root component of the React application. It sets up routing and manages the authentication state using local storage. It conditionally renders login, register, and chat components
*/
import React, { useState, useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import Login from './Login'
import Register from './Register'
import Chat from './Chat'
import './App.css'

function App() {
  // Track whether the user is authenticated
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  // On mount, check for an auth token in local storage to set the state
  useEffect(() => {
    const token = localStorage.getItem('authToken')
    if (token) {
      setIsAuthenticated(true)
    }
  }, [])

  // Update local storage and state when the user logs in
  const handleLogin = (token) => {
    localStorage.setItem('authToken', token)
    localStorage.setItem('username', token.split(':')[0])
    setIsAuthenticated(true)
  }

  // Remove user credentials and update state on logout
  const handleLogout = () => {
    localStorage.removeItem('authToken')
    localStorage.removeItem('username')
    setIsAuthenticated(false)
  }

  return (
    <Router>
      <Routes>
        <Route 
          path="/login" 
          element={isAuthenticated ? <Navigate to="/chat" /> : <Login onLogin={handleLogin} />} 
        />
        <Route 
          path="/register" 
          element={isAuthenticated ? <Navigate to="/chat" /> : <Register />} 
        />
        <Route 
          path="/chat" 
          element={isAuthenticated ? <Chat onLogout={handleLogout} /> : <Navigate to="/login" />} 
        />
        <Route path="*" element={<Navigate to="/login" />} />
      </Routes>
    </Router>
  )
}

export default App
