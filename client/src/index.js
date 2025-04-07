/*
index.js
This file is the entry point of the React application. It renders the App component into the DOM
*/
import React from 'react'
import ReactDOM from 'react-dom/client'
import './index.css'
import App from './App'
import reportWebVitals from './reportWebVitals'

const root = ReactDOM.createRoot(document.getElementById('root'))
root.render(
    <App />
)

reportWebVitals()
