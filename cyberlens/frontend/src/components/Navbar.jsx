import React from 'react'
import { Link, useLocation } from 'react-router-dom'

export default function Navbar() {
  const location = useLocation()
  const navLinks = [
    { path: '/', label: 'HOME' },
    { path: '/url', label: 'SCAN-URL' },
    { path: '/email', label: 'SCAN-EMAIL' },
    { path: '/audit', label: 'AUDIT' },
  ]

  return (
    <nav style={{
      position: 'fixed',
      top: 0, left: 0, right: 0,
      zIndex: 1000,
      background: 'rgba(5, 5, 8, 0.92)',
      backdropFilter: 'blur(12px)',
      borderBottom: '1px solid #1a1a2e',
      height: '60px',
      display: 'flex',
      alignItems: 'center',
      padding: '0 32px',
      justifyContent: 'space-between'
    }}>
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {/* Hexagon logo mark */}
        <div style={{
          width: '32px',
          height: '32px',
          background: 'linear-gradient(135deg, #7b2fff, #5500cc)',
          clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 0 15px rgba(123, 47, 255, 0.5)'
        }}>
          <span style={{ color: 'white', fontSize: '14px', fontWeight: '900', fontFamily: 'Orbitron' }}>C</span>
        </div>
        <div>
          <span style={{
            fontFamily: 'Orbitron',
            fontWeight: '800',
            fontSize: '16px',
            letterSpacing: '0.15em',
            color: '#7b2fff'
          }}>CYBER</span>
          <span style={{
            fontFamily: 'Orbitron',
            fontWeight: '400',
            fontSize: '16px',
            letterSpacing: '0.1em',
            color: '#f0f0ff'
          }}>LENS</span>
        </div>
      </div>

      {/* Nav links */}
      <div style={{ display: 'flex', gap: '4px' }}>
        {navLinks.map(link => {
          const active = location.pathname === link.path
          return (
            <Link key={link.path} to={link.path} style={{
              fontFamily: 'Orbitron',
              fontSize: '10px',
              fontWeight: '600',
              letterSpacing: '0.15em',
              padding: '8px 16px',
              color: active ? '#7b2fff' : '#7070a0',
              textDecoration: 'none',
              borderBottom: active ? '2px solid #7b2fff' : '2px solid transparent',
              transition: 'all 0.3s',
              position: 'relative'
            }}
            onMouseEnter={e => { if (!active) { e.target.style.color = '#f0f0ff'; e.target.style.borderBottomColor = '#7b2fff60'; }}}
            onMouseLeave={e => { if (!active) { e.target.style.color = '#7070a0'; e.target.style.borderBottomColor = 'transparent'; }}}
            >
              {link.label}
            </Link>
          )
        })}
      </div>

      {/* Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span className="node-online"></span>
        <span style={{
          fontFamily: 'Orbitron',
          fontSize: '9px',
          letterSpacing: '0.2em',
          color: '#39ff14'
        }}>NEURAL NET ONLINE</span>
      </div>
    </nav>
  )
}
