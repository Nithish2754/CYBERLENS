import React from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Navbar from './components/Navbar'
import Home from './pages/Home'
import URLScan from './pages/URLScan'
import EmailScan from './pages/EmailScan'

export default function App() {
  return (
    <BrowserRouter>
      <div style={{ background: '#030712', minHeight: '100vh' }}>
        <Navbar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/url" element={<URLScan />} />
          <Route path="/email" element={<EmailScan />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}
