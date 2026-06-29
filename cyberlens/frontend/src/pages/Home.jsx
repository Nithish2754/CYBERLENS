import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import logo from '../assets/layatech-logo.png'

export default function Home() {
  const navigate = useNavigate()
  const [showLine1, setShowLine1] = useState(false)
  const [showLine2, setShowLine2] = useState(false)
  const [showLine3, setShowLine3] = useState(false)

  useEffect(() => {
    setTimeout(() => setShowLine1(true), 200)
    setTimeout(() => setShowLine2(true), 400)
    setTimeout(() => setShowLine3(true), 600)
  }, [])

  return (
    <div style={{ flex: 1, padding: '40px', display: 'flex', flexDirection: 'column', gap: '60px', position: 'relative' }}>
      
      {/* Background Particles (CSS only logic applied here inline via simple styles if needed, or rely on neural-bg) */}

      {/* Hero Section */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', marginTop: '40px' }}>
        
        {/* Top Badge */}
        <div style={{
          border: '1px solid var(--accent-violet)',
          padding: '8px 24px',
          fontFamily: 'Share Tech Mono',
          fontSize: '12px',
          color: 'var(--accent-ice)',
          letterSpacing: '0.2em',
          clipPath: 'polygon(8px 0, calc(100% - 8px) 0, 100% 50%, calc(100% - 8px) 100%, 8px 100%, 0 50%)',
          marginBottom: '40px',
          background: 'rgba(123, 47, 255, 0.05)'
        }}>
          [ THREAT INTELLIGENCE PLATFORM v2.0 ]
        </div>

        {/* Main Heading */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '32px' }}>
          <h1 style={{
            fontFamily: 'Orbitron',
            fontWeight: 900,
            fontSize: '80px',
            color: '#fff',
            lineHeight: 1,
            opacity: showLine1 ? 1 : 0,
            transform: showLine1 ? 'translateY(0)' : 'translateY(20px)',
            transition: 'all 0.6s ease'
          }}>DETECT.</h1>
          
          <h1 style={{
            fontFamily: 'Orbitron',
            fontWeight: 900,
            fontSize: '80px',
            background: 'linear-gradient(90deg, #b983ff, #7b2fff)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            textShadow: '0 0 40px rgba(123, 47, 255, 0.4)',
            lineHeight: 1,
            opacity: showLine2 ? 1 : 0,
            transform: showLine2 ? 'translateY(0)' : 'translateY(20px)',
            transition: 'all 0.6s ease'
          }}>ANALYZE.</h1>
          
          <h1 style={{
            fontFamily: 'Orbitron',
            fontWeight: 900,
            fontSize: '80px',
            color: '#fff',
            lineHeight: 1,
            opacity: showLine3 ? 1 : 0,
            transform: showLine3 ? 'translateY(0)' : 'translateY(20px)',
            transition: 'all 0.6s ease'
          }}>PROTECT<span style={{ color: 'var(--accent-neon)', textShadow: '0 0 20px rgba(57, 255, 20, 0.6)' }}>.</span></h1>
        </div>

        {/* Subtext */}
        <p style={{
          fontFamily: 'Exo 2',
          fontSize: '18px',
          color: 'var(--text-secondary)',
          marginBottom: '48px',
          maxWidth: '600px',
          lineHeight: 1.6
        }}>
          Neural threat intelligence across 12+ security engines
        </p>

        {/* CTA Buttons */}
        <div style={{ display: 'flex', gap: '24px', marginBottom: '60px' }}>
          <button className="btn-scan" onClick={() => navigate('/url')}>
            ◈ SCAN URL
          </button>
          <button className="btn-scan" style={{ background: 'transparent', border: '1px solid var(--accent-neon)', color: 'var(--accent-neon)' }} onClick={() => navigate('/email')}
            onMouseEnter={e => { e.target.style.background = 'rgba(57, 255, 20, 0.1)'; e.target.style.boxShadow = '0 0 20px rgba(57, 255, 20, 0.3)'; }}
            onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.boxShadow = 'none'; }}>
            ⊠ ANALYZE EMAIL
          </button>
        </div>

        {/* Stat Indicators */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div style={{ fontFamily: 'Orbitron', fontSize: '12px', color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: 'var(--accent-violet)' }}>◈</span> 12+ SECURITY ENGINES
          </div>
          <div style={{ width: '30px', height: '1px', background: 'var(--border-dim)', transform: 'rotate(-45deg)' }}></div>
          <div style={{ fontFamily: 'Orbitron', fontSize: '12px', color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: 'var(--accent-ice)' }}>⬡</span> AI-NEURAL ANALYSIS
          </div>
          <div style={{ width: '30px', height: '1px', background: 'var(--border-dim)', transform: 'rotate(-45deg)' }}></div>
          <div style={{ fontFamily: 'Orbitron', fontSize: '12px', color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: 'var(--accent-neon)' }}>⚡</span> REAL-TIME DETECTION
          </div>
        </div>
      </div>

      <div className="diagonal-divider" style={{ margin: '40px -40px' }}></div>

      {/* Feature Cards Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '32px', maxWidth: '1200px', margin: '0 auto', width: '100%' }}>
        
        <div className="neural-card" style={{ padding: '32px', cursor: 'pointer' }} onClick={() => navigate('/url')}>
          <div style={{ width: '40px', height: '40px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-violet)', fontSize: '24px', marginBottom: '20px' }}>◈</div>
          <h3 className="neural-heading" style={{ fontSize: '16px', marginBottom: '12px' }}>URL THREAT SCAN</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: 1.6 }}>Multi-layer phishing detection across 12+ intelligence sources</p>
        </div>

        <div className="neural-card" style={{ padding: '32px', cursor: 'pointer', '--accent-violet': 'var(--accent-neon)' }} onClick={() => navigate('/email')}>
          <div style={{ width: '40px', height: '40px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-neon)', fontSize: '24px', marginBottom: '20px' }}>⊠</div>
          <h3 className="neural-heading" style={{ fontSize: '16px', marginBottom: '12px', color: 'var(--accent-neon)' }}>NEURAL EMAIL SCAN</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: 1.6 }}>AI-powered phishing pattern detection with header forensics</p>
        </div>

        <div className="neural-card" style={{ padding: '32px', cursor: 'pointer', '--accent-violet': 'var(--accent-ice)' }} onClick={() => navigate('/audit')}>
          <div style={{ width: '40px', height: '40px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-ice)', fontSize: '24px', marginBottom: '20px' }}>⬡</div>
          <h3 className="neural-heading" style={{ fontSize: '16px', marginBottom: '12px', color: 'var(--accent-ice)' }}>DEEP SITE AUDIT</h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px', lineHeight: 1.6 }}>Professional security assessment with OWASP and CVE mapping</p>
        </div>
      </div>

    </div>
  )
}
