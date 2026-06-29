import React, { useState, useEffect } from 'react'
import axios from 'axios'

const API_BASE = 'http://127.0.0.1:8000/api'

export default function URLScan() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [scanStatus, setScanStatus] = useState('Querying VirusTotal...')
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState(() => {
    const saved = localStorage.getItem('urlHistory')
    return saved ? JSON.parse(saved) : []
  })

  useEffect(() => {
    let interval;
    if (loading) {
      const statuses = [
        'Querying VirusTotal...',
        'Checking Safe Browsing...',
        'Running Pattern Analysis...',
        'Analyzing DNS...'
      ]
      let i = 0
      interval = setInterval(() => {
        i = (i + 1) % statuses.length
        setScanStatus(statuses[i])
      }, 2000)
    }
    return () => clearInterval(interval)
  }, [loading])

  const scanURL = async () => {
    if (!url.trim()) return

    setLoading(true)
    setResult(null)
    try {
      const response = await axios.post(`${API_BASE}/scan/url`, { url })
      const data = response.data

      setResult(data)

      const historyItem = {
        url: data.url,
        threat_level: data.threat_level,
        timestamp: new Date().toLocaleTimeString(),
      }
      const newHistory = [historyItem, ...history].slice(0, 10)
      setHistory(newHistory)
      localStorage.setItem('urlHistory', JSON.stringify(newHistory))
    } catch (error) {
      console.error('Error scanning URL:', error)
      alert('Error scanning URL. Please check the backend is running.')
    }
    setLoading(false)
  }

  const getScoreColor = (score) => {
    if (score <= 20) return 'var(--accent-neon)'
    if (score <= 65) return 'var(--accent-amber)'
    return 'var(--accent-crimson)'
  }

  const getLevelClass = (level) => {
    const l = (level || '').toLowerCase()
    if (l.includes('safe')) return 'hex-safe'
    if (l.includes('low')) return 'hex-low'
    if (l.includes('medium')) return 'hex-medium'
    if (l.includes('high')) return 'hex-high'
    if (l.includes('critical')) return 'hex-critical'
    return 'hex-safe'
  }

  return (
    <div style={{ padding: '40px', maxWidth: '1200px', margin: '0 auto', width: '100%', display: 'flex', flexDirection: 'column', gap: '40px' }}>
      
      {/* HEADER SECTION */}
      <div>
        <div className="section-label" style={{ marginBottom: '16px' }}>◈ THREAT INTELLIGENCE</div>
        <h1 className="neural-heading" style={{ fontSize: '48px', color: 'var(--accent-violet)', marginBottom: '8px' }}>URL SCANNER</h1>
        <div style={{ fontFamily: 'Share Tech Mono', color: 'var(--text-secondary)', fontSize: '14px' }}>
          $ target_analysis --mode=deep --engines=12
        </div>
      </div>

      {/* INPUT SECTION */}
      <div className="neural-card" style={{ padding: '32px' }}>
        <div className="section-label" style={{ marginBottom: '16px' }}>TARGET URL</div>
        <input 
          type="text" 
          className="neural-input" 
          placeholder="https://target-domain.com" 
          value={url}
          onChange={e => setUrl(e.target.value)}
          disabled={loading}
          onKeyDown={e => e.key === 'Enter' && scanURL()}
        />
        
        <div style={{ display: 'flex', gap: '16px', marginTop: '16px', marginBottom: '32px' }}>
          <button style={{ background: 'var(--bg-layer2)', border: '1px solid var(--accent-violet)', color: 'var(--text-primary)', padding: '6px 12px', fontSize: '10px', fontFamily: 'Orbitron', clipPath: 'polygon(6px 0, 100% 0, calc(100% - 6px) 100%, 0 100%)' }}>ALL ENGINES</button>
          <button style={{ background: 'transparent', border: '1px solid var(--border-dim)', color: 'var(--text-secondary)', padding: '6px 12px', fontSize: '10px', fontFamily: 'Orbitron', clipPath: 'polygon(6px 0, 100% 0, calc(100% - 6px) 100%, 0 100%)' }}>FAST SCAN</button>
          <button style={{ background: 'transparent', border: '1px solid var(--border-dim)', color: 'var(--text-secondary)', padding: '6px 12px', fontSize: '10px', fontFamily: 'Orbitron', clipPath: 'polygon(6px 0, 100% 0, calc(100% - 6px) 100%, 0 100%)' }}>DEEP SCAN</button>
        </div>

        <button className="btn-scan" onClick={scanURL} disabled={loading} style={{ width: '100%' }}>
          {loading ? 'INITIALIZING...' : 'INITIATE SCAN'}
        </button>

        {loading && (
          <div className="scanning-overlay" style={{ marginTop: '32px', padding: '40px 0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '24px', borderTop: '1px solid var(--border-dim)' }}>
            <div className="scan-beam"></div>
            
            {/* Hexagonal Loading Animation */}
            <div style={{ position: 'relative', width: '100px', height: '100px' }}>
              <svg viewBox="0 0 100 100" style={{ position: 'absolute', inset: 0, animation: 'border-rotate 4s linear infinite' }}>
                <polygon points="50 5, 90 25, 90 75, 50 95, 10 75, 10 25" fill="none" stroke="url(#hexGradient)" strokeWidth="2" />
                <defs>
                  <linearGradient id="hexGradient" x1="0%" y1="0%" x2="100%" y2="100%">
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
          
          {/* TOP ROW STATS */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px' }}>
            <div className="stat-card">
              <div className="section-label" style={{ marginBottom: '12px' }}>THREAT SCORE</div>
              <div style={{ fontSize: '36px', fontFamily: 'Share Tech Mono', color: getScoreColor(result.threat_score) }}>
                {result.threat_score}<span style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>/100</span>
              </div>
            </div>
            <div className="stat-card">
              <div className="section-label" style={{ marginBottom: '12px' }}>THREAT LEVEL</div>
              <div className={`hex-badge ${getLevelClass(result.threat_level)}`} style={{ marginTop: '8px', fontSize: '14px', padding: '12px 24px' }}>
                {result.threat_level}
              </div>
            </div>
            <div className="stat-card">
              <div className="section-label" style={{ marginBottom: '12px' }}>ENGINES CHECKED</div>
              <div style={{ fontSize: '36px', fontFamily: 'Share Tech Mono', color: 'var(--accent-ice)' }}>
                12<span style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>+</span>
              </div>
            </div>
          </div>

          {/* MAIN GRID */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '32px' }}>
            
            {/* SVG Score Ring */}
            <div className="neural-card" style={{ padding: '40px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '24px' }}>
              <div className="section-label" style={{ alignSelf: 'flex-start', width: '100%' }}>OVERALL RISK</div>
              
              <div className="score-ring-container" style={{ width: '200px', height: '200px' }}>
                <svg width="200" height="200" viewBox="0 0 200 200">
                  {/* Background track */}
                  <circle cx="100" cy="100" r="80" fill="none" stroke="var(--bg-layer3)" strokeWidth="12" />
                  {/* Score arc */}
                  <circle 
                    cx="100" cy="100" r="80" 
                    fill="none" 
                    stroke={getScoreColor(result.threat_score)} 
                    strokeWidth="12" 
                    strokeDasharray={`${(result.threat_score / 100) * 502.6} 502.6`}
                    strokeLinecap="round"
                    transform="rotate(-90 100 100)"
                    style={{ transition: 'stroke-dasharray 1s ease-out, stroke 1s ease' }}
                  />
                  {/* Inner decorative dashed ring */}
                  <circle cx="100" cy="100" r="65" fill="none" stroke="var(--border-dim)" strokeWidth="1" strokeDasharray="4 4" />
                </svg>
                <div className="score-value" style={{ color: getScoreColor(result.threat_score) }}>{result.threat_score}</div>
                <div className="score-label">SCORE</div>
              </div>
            </div>

            {/* Threat Matrix */}
            <div className="neural-card" style={{ padding: '32px' }}>
              <div className="section-label" style={{ marginBottom: '24px' }}>THREAT MATRIX</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {result.reasons && result.reasons.length > 0 ? (
                  result.reasons.map((reason, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', fontFamily: 'Share Tech Mono', fontSize: '14px', background: 'var(--bg-layer2)', padding: '12px 16px', borderLeft: '2px solid var(--accent-amber)' }}>
                      <span style={{ color: 'var(--accent-amber)' }}>▸</span>
                      <span style={{ color: 'var(--text-primary)' }}>{reason}</span>
                    </div>
                  ))
                ) : (
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', fontFamily: 'Share Tech Mono', fontSize: '14px', background: 'var(--bg-layer2)', padding: '12px 16px', borderLeft: '2px solid var(--accent-neon)' }}>
                    <span style={{ color: 'var(--accent-neon)' }}>▸</span>
                    <span style={{ color: 'var(--accent-neon)' }}>No significant threats detected in standard matrix.</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* AI Assessment */}
          <div style={{ background: 'var(--bg-layer2)', border: '1px solid var(--border-dim)', borderLeft: '4px solid var(--accent-violet)', padding: '32px', position: 'relative' }}>
            <div className="section-label" style={{ marginBottom: '16px' }}>NEURAL ASSESSMENT</div>
            <p style={{ fontFamily: 'Exo 2', fontSize: '15px', lineHeight: '1.8', color: 'var(--text-primary)' }}>
              {result.ai_explanation}
            </p>
          </div>

          {/* Pattern Analysis */}
          {result.pattern_analysis && result.pattern_analysis.flags_count > 0 && (
            <div className="neon-card" style={{ padding: '32px' }}>
              <div className="section-label" style={{ marginBottom: '24px', color: 'var(--accent-crimson)' }}>PATTERN ANALYSIS DETECTIONS</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {result.pattern_analysis.flags.map((flag, idx) => (
                  <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-layer2)', padding: '12px 16px', border: '1px solid rgba(255, 23, 68, 0.2)' }}>
                    <div style={{ fontFamily: 'Share Tech Mono', fontSize: '14px', color: 'var(--text-primary)', display: 'flex', gap: '12px' }}>
                      <span style={{ color: 'var(--accent-crimson)' }}>▸</span>
                      {flag}
                    </div>
                    <div className="hex-badge hex-critical" style={{ fontSize: '9px', padding: '4px 12px' }}>FLAGGED</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Intelligence Sources */}
          <div>
            <div className="section-label" style={{ marginBottom: '24px' }}>INTELLIGENCE SOURCES</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '16px' }}>
              
              {/* VT */}
              <div className={`intel-source ${(result.virustotal && result.virustotal.malicious > 0) ? 'flagged' : 'clean'}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>VIRUSTOTAL</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '18px', color: 'var(--text-primary)' }}>
                  {result.virustotal ? `${result.virustotal.malicious}/${result.virustotal.total_engines}` : '--'}
                </div>
              </div>

              {/* Safe Browsing */}
              <div className={`intel-source ${(result.safe_browsing && result.safe_browsing.is_threat) ? 'flagged' : 'clean'}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>SAFE BROWSING</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '12px', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                  {result.safe_browsing && result.safe_browsing.is_threat ? 'THREAT FOUND' : 'CLEAN'}
                </div>
              </div>

              {/* URLScan */}
              <div className={`intel-source ${(result.urlscan && result.urlscan.malicious) ? 'flagged' : (result.urlscan && result.urlscan.available !== false ? 'clean' : 'unavailable')}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>URLSCAN.IO</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '14px', color: 'var(--text-primary)' }}>
                  {result.urlscan && result.urlscan.malicious ? 'MALICIOUS' : (result.urlscan && result.urlscan.score !== undefined ? `SCORE: ${result.urlscan.score}` : 'CLEAN')}
                </div>
              </div>

              {/* PhishTank */}
              <div className={`intel-source ${(result.phishtank && result.phishtank.in_database) ? 'flagged' : (result.phishtank && result.phishtank.available !== false ? 'clean' : 'unavailable')}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>PHISHTANK</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '12px', color: 'var(--text-primary)' }}>
                  {result.phishtank && result.phishtank.in_database ? `ID:${result.phishtank.phish_id}` : 'NOT LISTED'}
                </div>
              </div>

              {/* IPQS */}
              <div className={`intel-source ${(result.ipqs && (result.ipqs.phishing || result.ipqs.suspicious || result.ipqs.risk_score > 70)) ? 'flagged' : (result.ipqs && result.ipqs.available !== false ? 'clean' : 'unavailable')}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>IP QUALITY SCORE</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '18px', color: 'var(--text-primary)' }}>
                  {result.ipqs && result.ipqs.risk_score !== undefined ? `${result.ipqs.risk_score}/100` : '--'}
                </div>
              </div>

              {/* DNS */}
              <div className={`intel-source ${(result.dns_analysis && (!result.dns_analysis.resolved || result.dns_analysis.dns_score > 20)) ? 'flagged' : 'clean'}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>DNS ANALYSIS</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '18px', color: 'var(--text-primary)' }}>
                  {result.dns_analysis ? `${result.dns_analysis.dns_score} PTS` : '--'}
                </div>
              </div>

              {/* SSL */}
              <div className={`intel-source ${(result.ssl_analysis && result.ssl_analysis.valid === false) ? 'flagged' : (result.ssl_analysis && result.ssl_analysis.available !== false ? 'clean' : 'unavailable')}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>SSL CERTIFICATE</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '12px', color: 'var(--text-primary)' }}>
                  {result.ssl_analysis && result.ssl_analysis.valid === false ? 'INVALID' : 'VALID'}
                </div>
              </div>

              {/* Domain */}
              <div className={`intel-source ${(result.domain_analysis && result.domain_analysis.heuristic_score > 20) ? 'flagged' : 'clean'}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>DOMAIN AGE</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '18px', color: 'var(--text-primary)' }}>
                  {result.domain_analysis ? `${result.domain_analysis.heuristic_score} PTS` : '--'}
                </div>
              </div>

              {/* Redirects */}
              <div className={`intel-source ${(result.redirect_analysis && result.redirect_analysis.redirect_score > 20) ? 'flagged' : 'clean'}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>REDIRECT CHAIN</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '18px', color: 'var(--text-primary)' }}>
                  {result.redirect_analysis ? `${result.redirect_analysis.redirect_count} HOPS` : '--'}
                </div>
              </div>

              {/* Pattern */}
              <div className={`intel-source ${(result.pattern_analysis && result.pattern_analysis.flags_count > 0) ? 'flagged' : 'clean'}`}>
                <div style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)', marginBottom: '12px' }}>PATTERN AI</div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '18px', color: 'var(--text-primary)' }}>
                  {result.pattern_analysis ? `${result.pattern_analysis.pattern_score} PTS` : '--'}
                </div>
              </div>

            </div>
          </div>
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
              onClick={() => setUrl(item.url)}
              >
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '14px', color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {item.url}
                </div>
                <div className={`hex-badge ${getLevelClass(item.threat_level)}`} style={{ padding: '4px 12px', fontSize: '9px' }}>
                  {item.threat_level}
                </div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '12px', color: 'var(--text-secondary)' }}>
                  {item.timestamp}
                </div>
              </div>
            ))}
          </div>
          <button style={{ marginTop: '16px', background: 'transparent', border: 'none', color: 'var(--text-secondary)', fontFamily: 'Orbitron', fontSize: '10px', letterSpacing: '0.1em', cursor: 'pointer' }} onClick={() => { setHistory([]); localStorage.removeItem('urlHistory'); }}>
            [ CLEAR SYSTEM LOG ]
          </button>
        </div>
      )}

    </div>
  )
}
