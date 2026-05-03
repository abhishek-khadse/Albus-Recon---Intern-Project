import React from 'react'
import ReactDOM from 'react-dom/client'
// No more BrowserRouter import here
import App from './App.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)