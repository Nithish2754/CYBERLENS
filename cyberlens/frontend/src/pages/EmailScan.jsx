import React, { useState, useEffect } from 'react'
import axios from 'axios'

const API_BASE = 'http://127.0.0.1:8000/api'

export default function EmailScan() {
  const [emailText, setEmailText] = useState('')
  const [loading, setLoading] = useState(false)
  const [scanStatus, setScanStatus] = useState('Extracting headers...')
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState(() => {
    const saved = localStorage.getItem('emailHistory')
    return saved ? JSON.parse(saved) : []
  })

  useEffect(() => {
    let interval;
    if (loading) {
      const statuses = [
        'Extracting headers...',
        'Analyzing neural patterns...',
        'Checking sender reputation...',
        'Evaluating embedded links...'
      ]
      let i = 0
      interval = setInterval(() => {
        i = (i + 1) % statuses.length
        setScanStatus(statuses[i])
      }, 2000)
    }
    return () => clearInterval(interval)
  }, [loading])

  const analyzeEmail = async () => {
    if (!emailText.trim()) return

    setLoading(true)
    setResult(null)
    try {
      const response = await axios.post(`${API_BASE}/scan/email`, { email_text: emailText })
      const data = response.data

      setResult(data)

      const historyItem = {
        subject: data.metadata.subject || 'Unknown',
        threat_level: data.threat_level,
        verdict: data.verdict,
        timestamp: new Date().toLocaleTimeString(),
      }
      const newHistory = [historyItem, ...history].slice(0, 10)
      setHistory(newHistory)
      localStorage.setItem('emailHistory', JSON.stringify(newHistory))
    } catch (error) {
      console.error('Error analyzing email:', error)
      alert('Error analyzing email. Please check the backend is running.')
    }
    setLoading(false)
  }

  const getScoreColor = (score) => {
    if (score <= 20) return 'var(--accent-neon)'
    if (score <= 65) return 'var(--accent-amber)'
    return 'var(--accent-crimson)'
  }

  const getVerdictClass = (verdict) => {
    const v = (verdict || '').toLowerCase()
    if (v.includes('safe')) return 'hex-safe'
    if (v.includes('suspicious')) return 'hex-medium'
    if (v.includes('phishing')) return 'hex-critical'
    return 'hex-safe'
  }

  return (
    <div style={{ padding: '40px', maxWidth: '1200px', margin: '0 auto', width: '100%', display: 'flex', flexDirection: 'column', gap: '40px' }}>
      
      {/* HEADER SECTION */}
      <div>
        <div className="section-label" style={{ marginBottom: '16px' }}>◈ THREAT INTELLIGENCE</div>
        <h1 className="neural-heading" style={{ fontSize: '48px', color: 'var(--accent-violet)', marginBottom: '8px' }}>EMAIL FORENSICS</h1>
        <div style={{ fontFamily: 'Share Tech Mono', color: 'var(--text-secondary)', fontSize: '14px' }}>
          $ target_analysis --mode=email_deep_scan
        </div>
      </div>

      {/* INPUT SECTION */}
      <div className="neural-card" style={{ padding: '32px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '16px' }}>
          <div className="section-label">PASTE EMAIL CONTENT</div>
          <div style={{ fontFamily: 'Share Tech Mono', fontSize: '10px', color: 'var(--text-secondary)' }}>
            CHARS: {emailText.length} | LINES: {emailText.split('\n').length}
          </div>
        </div>
        
        <textarea 
          className="neural-textarea" 
          placeholder="Paste raw email source or content here..." 
          value={emailText}
          onChange={e => setEmailText(e.target.value)}
          disabled={loading}
        />
        
        <div style={{ marginTop: '32px' }}>
          <button className="btn-scan" onClick={analyzeEmail} disabled={loading} style={{ width: '100%' }}>
            {loading ? 'ANALYZING...' : 'ANALYZE THREAT PATTERN'}
          </button>
        </div>

        {loading && (
          <div className="scanning-overlay" style={{ marginTop: '32px', padding: '40px 0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '24px', borderTop: '1px solid var(--border-dim)' }}>
            <div className="scan-beam"></div>
            
            <div style={{ position: 'relative', width: '100px', height: '100px' }}>
              <svg viewBox="0 0 100 100" style={{ position: 'absolute', inset: 0, animation: 'border-rotate 4s linear infinite' }}>
                <polygon points="50 5, 90 25, 90 75, 50 95, 10 75, 10 25" fill="none" stroke="url(#hexGradientE)" strokeWidth="2" />
                <defs>
                  <linearGradient id="hexGradientE" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="var(--accent-violet)" />
                    <stop offset="50%" stopColor="var(--accent-neon)" />
                    <stop offset="100%" stopColor="transparent" />
                  </linearGradient>
                </defs>
              </svg>
              <svg viewBox="0 0 100 100" style={{ position: 'absolute', inset: 15, animation: 'border-rotate 3s linear infinite reverse' }}>
                <polygon points="50 5, 90 25, 90 75, 50 95, 10 75, 10 25" fill="none" stroke="rgba(123, 47, 255, 0.3)" strokeWidth="1" strokeDasharray="5,5" />
              </svg>
              <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <span style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--accent-violet)', animation: 'blink-text 1s infinite' }}>SCAN</span>
              </div>
            </div>
            
            <div style={{ fontFamily: 'Share Tech Mono', color: 'var(--accent-ice)', fontSize: '14px' }}>
              {scanStatus}
            </div>
          </div>
        )}
      </div>

      {/* RESULTS SECTION */}
      {result && !loading && (
        <div className="fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: '40px' }}>
          
          {/* TOP ROW */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px' }}>
            <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <div className="section-label" style={{ marginBottom: '16px' }}>VERDICT</div>
              <div className={`hex-badge ${getVerdictClass(result.verdict)}`} style={{ fontSize: '18px', padding: '16px 32px' }}>
                {result.verdict.toUpperCase()}
              </div>
            </div>
            
            <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <div className="section-label" style={{ marginBottom: '16px' }}>RISK SCORE</div>
              <div className="score-ring-container" style={{ width: '120px', height: '120px' }}>
                <svg width="120" height="120" viewBox="0 0 120 120">
                  <circle cx="60" cy="60" r="50" fill="none" stroke="var(--bg-layer3)" strokeWidth="8" />
                  <circle 
                    cx="60" cy="60" r="50" 
                    fill="none" 
                    stroke={getScoreColor(result.threat_score)} 
                    strokeWidth="8" 
                    strokeDasharray={`${(result.threat_score / 100) * 314.15} 314.15`}
                    strokeLinecap="round"
                    transform="rotate(-90 60 60)"
                  />
                </svg>
                <div className="score-value" style={{ fontSize: '24px', color: getScoreColor(result.threat_score) }}>{result.threat_score}</div>
              </div>
            </div>
            
            <div className="stat-card">
              <div className="section-label" style={{ marginBottom: '16px' }}>METADATA</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'Share Tech Mono', fontSize: '12px' }}>
                <div><span style={{ color: 'var(--text-secondary)' }}>SENDER:</span> <span style={{ color: 'var(--accent-ice)' }}>{result.metadata.sender}</span></div>
                <div><span style={{ color: 'var(--text-secondary)' }}>SUBJECT:</span> <span style={{ color: 'var(--accent-ice)' }}>{result.metadata.subject}</span></div>
                <div><span style={{ color: 'var(--text-secondary)' }}>URLS:</span> <span style={{ color: 'var(--accent-ice)' }}>{result.metadata.url_count}</span></div>
                <div><span style={{ color: 'var(--text-secondary)' }}>WORDS:</span> <span style={{ color: 'var(--accent-ice)' }}>{result.metadata.word_count}</span></div>
              </div>
            </div>
          </div>

          {/* MAIN SECTION */}
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '32px' }}>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
              <div style={{ background: 'var(--bg-layer2)', border: '1px solid var(--border-dim)', borderLeft: '4px solid var(--accent-violet)', padding: '32px' }}>
                <div className="section-label" style={{ marginBottom: '16px' }}>AI THREAT ANALYSIS</div>
                <p style={{ fontFamily: 'Exo 2', fontSize: '15px', lineHeight: '1.8', color: 'var(--text-primary)' }}>
                  {result.summary}
                </p>
              </div>

              <div className="neon-card" style={{ padding: '32px', borderColor: result.indicators.length > 0 ? 'var(--accent-crimson)' : 'var(--accent-neon)' }}>
                <div className="section-label" style={{ marginBottom: '24px', color: result.indicators.length > 0 ? 'var(--accent-crimson)' : 'var(--accent-neon)' }}>PHISHING INDICATORS</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {result.indicators.length > 0 ? result.indicators.map((indicator, idx) => (
                    <div key={idx} style={{ display: 'flex', gap: '12px', fontFamily: 'Share Tech Mono', fontSize: '14px', background: 'var(--bg-layer2)', padding: '12px 16px' }}>
                      <span style={{ color: 'var(--accent-crimson)' }}>▸</span>
                      <span style={{ color: 'var(--text-primary)' }}>{indicator}</span>
                    </div>
                  )) : (
                    <div style={{ display: 'flex', gap: '12px', fontFamily: 'Share Tech Mono', fontSize: '14px', background: 'var(--bg-layer2)', padding: '12px 16px' }}>
                      <span style={{ color: 'var(--accent-neon)' }}>▸</span>
                      <span style={{ color: 'var(--text-primary)' }}>No phishing indicators found.</span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
              <div className="neural-card" style={{ padding: '32px' }}>
                <div className="section-label" style={{ marginBottom: '24px' }}>HEADER FORENSICS</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontFamily: 'Orbitron', fontSize: '12px', color: 'var(--text-secondary)' }}>SPF</span>
                    <span className="hex-badge hex-medium">MISSING</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontFamily: 'Orbitron', fontSize: '12px', color: 'var(--text-secondary)' }}>DKIM</span>
                    <span className="hex-badge hex-medium">MISSING</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontFamily: 'Orbitron', fontSize: '12px', color: 'var(--text-secondary)' }}>DMARC</span>
                    <span className="hex-badge hex-medium">MISSING</span>
                  </div>
                  <div style={{ marginTop: '16px', fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'Share Tech Mono' }}>
                    * Advanced header parsing requires raw EML source.
                  </div>
                </div>
              </div>

              <div style={{ background: 'var(--bg-layer2)', borderLeft: `4px solid ${result.verdict === 'Phishing' ? 'var(--accent-crimson)' : 'var(--accent-amber)'}`, padding: '32px' }}>
                <div className="section-label" style={{ marginBottom: '16px', color: result.verdict === 'Phishing' ? 'var(--accent-crimson)' : 'var(--accent-amber)' }}>RECOMMENDED ACTION</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '14px', color: 'var(--text-primary)', lineHeight: '1.6' }}>
                  {result.recommended_action}
                </div>
              </div>
            </div>

          </div>

          {/* EXTRACTED URLS */}
          {result.extracted_urls && result.extracted_urls.length > 0 && (
            <div>
              <div className="section-label" style={{ marginBottom: '24px' }}>EMBEDDED TARGETS</div>
              <div style={{ background: 'var(--bg-layer1)', border: '1px solid var(--border-dim)' }}>
                {result.extracted_urls.map((item, idx) => (
                  <div key={idx} style={{ 
                    display: 'grid', 
                    gridTemplateColumns: '1fr auto auto', 
                    gap: '24px', 
                    padding: '16px 24px', 
                    borderBottom: idx < result.extracted_urls.length - 1 ? '1px solid var(--border-dim)' : 'none',
                    alignItems: 'center'
                  }}>
                    <div style={{ fontFamily: 'Share Tech Mono', fontSize: '14px', color: 'var(--text-secondary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {item.url}
                    </div>
                    <div style={{ fontFamily: 'Share Tech Mono', fontSize: '12px', color: 'var(--text-secondary)' }}>
                      VT: {item.malicious}
                    </div>
                    <div className={`hex-badge ${item.malicious > 0 ? 'hex-critical' : 'hex-safe'}`} style={{ padding: '4px 12px', fontSize: '9px' }}>
                      {item.malicious > 0 ? 'DANGEROUS' : 'CLEAN'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* SCAN HISTORY */}
      {history.length > 0 && (
        <div style={{ marginTop: '40px' }}>
          <div className="section-label" style={{ marginBottom: '24px' }}>PREVIOUS TARGETS</div>
          <div style={{ background: 'var(--bg-layer1)', border: '1px solid var(--border-dim)' }}>
            {history.map((item, idx) => (
              <div key={idx} style={{ 
                display: 'grid', 
                gridTemplateColumns: '1fr auto auto', 
                gap: '24px', 
                padding: '16px 24px', 
                borderBottom: idx < history.length - 1 ? '1px solid var(--border-dim)' : 'none',
                alignItems: 'center',
                cursor: 'pointer',
                transition: 'background 0.3s'
              }}
              className="glitch-hover"
              onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-layer2)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              onClick={() => setEmailText('')}
              >
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '14px', color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {item.subject}
                </div>
                <div className={`hex-badge ${getVerdictClass(item.verdict)}`} style={{ padding: '4px 12px', fontSize: '9px' }}>
                  {item.verdict ? item.verdict.toUpperCase() : 'UNKNOWN'}
                </div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '12px', color: 'var(--text-secondary)' }}>
                  {item.timestamp}
                </div>
              </div>
            ))}
          </div>
          <button style={{ marginTop: '16px', background: 'transparent', border: 'none', color: 'var(--text-secondary)', fontFamily: 'Orbitron', fontSize: '10px', letterSpacing: '0.1em', cursor: 'pointer' }} onClick={() => { setHistory([]); localStorage.removeItem('emailHistory'); }}>
            [ CLEAR SYSTEM LOG ]
          </button>
        </div>
      )}

    </div>
  )
}
