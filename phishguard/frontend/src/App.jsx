import React from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Navbar from './components/Navbar'
import Home from './pages/Home'
import URLScan from './pages/URLScan'
import EmailScan from './pages/EmailScan'
import WebsiteAudit from './pages/WebsiteAudit'
import Footer from './components/Footer'

export default function App() {
  return (
    <BrowserRouter>
      <div style={{ background: '#030712', minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
        <Navbar />
        <div style={{ flex: 1 }}>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/url" element={<URLScan />} />
            <Route path="/email" element={<EmailScan />} />
            <Route path="/audit" element={<WebsiteAudit />} />
          </Routes>
        </div>
        <Footer />
      </div>
    </BrowserRouter>
  )
}
