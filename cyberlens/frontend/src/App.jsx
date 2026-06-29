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
      <div style={{ background: 'var(--bg-void)', minHeight: '100vh', display: 'flex', flexDirection: 'column', paddingTop: '60px' }}>
        <div className="neural-bg" />
        <div style={{ position: 'relative', zIndex: 1, flex: 1, display: 'flex', flexDirection: 'column' }}>
          <Navbar />
          <div style={{ flex: 1 }}>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/url" element={<URLScan />} />
              <Route path="/email" element={<EmailScan />} />
              <Route path="/audit" element={<WebsiteAudit />} />
            </Routes>
          </div>
        </div>
        <Footer />
      </div>
    </BrowserRouter>
  )
}
