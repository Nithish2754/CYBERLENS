import React from 'react'
import logo from '../assets/layatech-logo.png'

export default function Footer() {
  return (
    <footer style={{
      background: 'rgba(10, 10, 20, 0.98)',
      borderTop: '1px solid #1a1a2e',
      marginTop: 'auto',
      padding: '20px 40px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      clipPath: 'polygon(0 8px, 20px 0, 100% 0, 100% 100%, 0 100%)',
      fontFamily: 'Orbitron, sans-serif'
    }}>
      {/* Left: Logo Name */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ color: '#7b2fff', fontWeight: '800', fontSize: '12px', letterSpacing: '0.15em' }}>CYBER</span>
        <span style={{ color: '#f0f0ff', fontWeight: '400', fontSize: '12px', letterSpacing: '0.1em' }}>LENS</span>
      </div>

      {/* Center: Internship Credit */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <span style={{ color: '#7070a0', fontSize: '10px', letterSpacing: '0.1em' }}>DEVELOPED AT ▸</span>
        <div style={{
          background: 'rgba(255,255,255,0.05)',
          padding: '4px 12px',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          borderLeft: '2px solid #7b2fff'
        }}>
          <img src={logo} alt="Laya Tech" style={{ height: '20px', filter: 'drop-shadow(0 0 5px rgba(255,255,255,0.2))' }} />
          <span style={{ color: '#f0f0ff', fontSize: '10px', letterSpacing: '0.1em' }}>▸ CYBERSECURITY INTERNSHIP 2026</span>
        </div>
      </div>

      {/* Right: Copyright/Status */}
      <div style={{ color: '#404060', fontSize: '10px', letterSpacing: '0.1em' }}>
        © 2026 — ALL SYSTEMS OPERATIONAL
      </div>
    </footer>
  )
}
