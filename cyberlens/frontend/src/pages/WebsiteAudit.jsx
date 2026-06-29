import React, { useState, useEffect, useMemo } from 'react'
import axios from 'axios'

const API_BASE = 'http://127.0.0.1:8000/api'

const scanSteps = [
  '🛡 Checking SSL/TLS security...',
  'Headers Evaluating security headers...',
  '🌐 Analyzing DNS security...',
  '⭐ Checking domain reputation...',
  '⚡ Assessing vulnerabilities...',
  '🔍 Gathering threat intelligence...',
  '🍪 Verifying cookie security...',
  '🤖 Matching known CVE vulnerabilities...',
  '📊 Mapping compliance frameworks...',
]

export default function WebsiteAudit() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [stepIndex, setStepIndex] = useState(0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!loading) return
    setStepIndex(0)
    const iv = setInterval(() => setStepIndex(i => (i + 1) % scanSteps.length), 1100)
    return () => clearInterval(iv)
  }, [loading])

  const performAudit = async () => {
    if (!url.trim()) return
    setError(null)
    setLoading(true)
    setResult(null)
    try {
      const normalized = url.trim().startsWith('http') ? url.trim() : `https://${url.trim()}`
      const res = await axios.post(`${API_BASE}/audit`, { url: normalized })
      setResult(res.data)
    } catch (err) {
      setError('Could not run the audit. Please verify the backend is running and the URL is reachable.')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const getScoreColor = (score) => {
    if (score >= 80) return 'var(--accent-neon)'
    if (score >= 60) return 'var(--accent-ice)'
    if (score >= 40) return 'var(--accent-amber)'
    return 'var(--accent-crimson)'
  }

  const categories = useMemo(() => {
    if (!result || !result.categories) return []
    return [
      { key: 'ssl_tls', label: 'SSL/TLS SECURITY', color: 'var(--accent-violet)', score: result.categories.ssl_tls?.score || 0 },
      { key: 'headers', label: 'SECURITY HEADERS', color: 'var(--accent-ice)', score: result.categories.headers?.score || 0 },
      { key: 'dns', label: 'DNS SECURITY', color: 'var(--accent-amber)', score: result.categories.dns?.score || 0 },
      { key: 'vulns', label: 'VULNERABILITIES', color: 'var(--accent-neon)', score: result.categories.vulns?.score || 0 }
    ]
  }, [result])

  return (
    <div style={{ padding: '40px', maxWidth: '1200px', margin: '0 auto', width: '100%', display: 'flex', flexDirection: 'column', gap: '40px' }}>
      
      {/* HEADER SECTION */}
      <div>
        <div className="section-label" style={{ marginBottom: '16px' }}>◈ INTELLIGENCE MODULE</div>
        <h1 className="neural-heading" style={{ fontSize: '48px', color: 'var(--accent-violet)', marginBottom: '8px' }}>SITE INTELLIGENCE AUDIT</h1>
        <div style={{ fontFamily: 'Share Tech Mono', color: 'var(--text-secondary)', fontSize: '14px' }}>
          $ target_analysis --mode=audit --deep=true
        </div>
      </div>

      {/* INPUT SECTION */}
      <div className="neural-card" style={{ padding: '32px' }}>
        <div className="section-label" style={{ marginBottom: '16px' }}>TARGET URL</div>
        <input 
          type="text" 
          className="neural-input" 
          placeholder="https://example.com" 
          value={url}
          onChange={e => setUrl(e.target.value)}
          disabled={loading}
          onKeyDown={e => e.key === 'Enter' && performAudit()}
        />
        
        <div style={{ marginTop: '32px' }}>
          <button className="btn-scan" onClick={performAudit} disabled={loading} style={{ width: '100%' }}>
            {loading ? 'INITIALIZING...' : 'LAUNCH AUDIT'}
          </button>
        </div>

        {loading && (
          <div className="scanning-overlay" style={{ marginTop: '32px', padding: '40px 0', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '24px', borderTop: '1px solid var(--border-dim)' }}>
            <div className="scan-beam"></div>
            <div style={{ position: 'relative', width: '100px', height: '100px' }}>
              <svg viewBox="0 0 100 100" style={{ position: 'absolute', inset: 0, animation: 'border-rotate 4s linear infinite' }}>
                <polygon points="50 5, 90 25, 90 75, 50 95, 10 75, 10 25" fill="none" stroke="url(#hexGradientA)" strokeWidth="2" />
                <defs>
                  <linearGradient id="hexGradientA" x1="0%" y1="0%" x2="100%" y2="100%">
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
                <span style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--accent-violet)', animation: 'blink-text 1s infinite' }}>AUDIT</span>
              </div>
            </div>
            <div style={{ fontFamily: 'Share Tech Mono', color: 'var(--accent-ice)', fontSize: '14px' }}>
              {scanSteps[stepIndex]}
            </div>
          </div>
        )}
        
        {error && (
          <div style={{ marginTop: '24px', color: 'var(--accent-crimson)', fontFamily: 'Share Tech Mono', fontSize: '14px', background: 'rgba(255,23,68,0.1)', padding: '16px', borderLeft: '4px solid var(--accent-crimson)' }}>
            {error}
          </div>
        )}
      </div>

      {/* RESULTS SECTION */}
      {result && !loading && (
        <div className="fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: '40px' }}>
          
          {/* TOP RESULTS */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '24px' }}>
            
            {/* SVG Ring Score */}
            <div className="neural-card" style={{ padding: '32px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <div className="section-label" style={{ alignSelf: 'flex-start', marginBottom: '24px' }}>OVERALL SCORE</div>
              <div className="score-ring-container" style={{ width: '160px', height: '160px' }}>
                <svg width="160" height="160" viewBox="0 0 160 160">
                  <circle cx="80" cy="80" r="70" fill="none" stroke="var(--bg-layer3)" strokeWidth="10" />
                  <circle 
                    cx="80" cy="80" r="70" 
                    fill="none" 
                    stroke={getScoreColor(result.overall_score)} 
                    strokeWidth="10" 
                    strokeDasharray={`${(result.overall_score / 100) * 439.8} 439.8`}
                    strokeLinecap="round"
                    transform="rotate(-90 80 80)"
                  />
                </svg>
                <div className="score-value" style={{ fontSize: '32px', color: getScoreColor(result.overall_score) }}>
                  {result.overall_score}
                </div>
              </div>
            </div>

            {/* Huge Hex Grade */}
            <div className="neural-card" style={{ padding: '32px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <div className="section-label" style={{ alignSelf: 'flex-start', marginBottom: '24px' }}>GRADE</div>
              <div style={{
                width: '140px',
                height: '140px',
                background: `linear-gradient(135deg, ${getScoreColor(result.overall_score)}20, transparent)`,
                border: `2px solid ${getScoreColor(result.overall_score)}`,
                clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                boxShadow: `0 0 30px ${getScoreColor(result.overall_score)}40`
              }}>
                <span style={{ fontFamily: 'Orbitron', fontWeight: 900, fontSize: '64px', color: getScoreColor(result.overall_score), textShadow: `0 0 20px ${getScoreColor(result.overall_score)}` }}>
                  {result.grade}
                </span>
              </div>
            </div>

            {/* AI Summary */}
            <div className="neural-card" style={{ padding: '32px', borderLeft: '4px solid var(--accent-violet)' }}>
              <div className="section-label" style={{ marginBottom: '16px' }}>AI EXECUTIVE SUMMARY</div>
              <p style={{ fontFamily: 'Exo 2', fontSize: '14px', lineHeight: '1.8', color: 'var(--text-primary)' }}>
                {result.ai_summary || "Automated neural assessment completed. Review the individual module scores and compliance vectors for specific vulnerability details."}
              </p>
            </div>
          </div>

          {/* 4 CATEGORY SCORE BARS */}
          <div className="neural-card" style={{ padding: '32px' }}>
            <div className="section-label" style={{ marginBottom: '32px' }}>MODULE ASSESSMENT</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px' }}>
              {categories.map((cat, idx) => (
                <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'Orbitron', fontSize: '12px', letterSpacing: '0.1em' }}>
                    <span style={{ color: cat.color }}>{cat.label}</span>
                    <span style={{ color: 'var(--text-primary)' }}>{cat.score}/100</span>
                  </div>
                  {/* Angular progress bar */}
                  <div style={{ width: '100%', height: '8px', background: 'var(--bg-layer3)', clipPath: 'polygon(6px 0, 100% 0, calc(100% - 6px) 100%, 0 100%)' }}>
                    <div style={{ width: `${cat.score}%`, height: '100%', background: cat.color, transition: 'width 1s ease', clipPath: 'polygon(6px 0, 100% 0, calc(100% - 6px) 100%, 0 100%)', boxShadow: `0 0 10px ${cat.color}` }}></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* ISSUES COLLAPSIBLE SECTIONS */}
          <div>
            <div className="section-label" style={{ marginBottom: '24px' }}>VULNERABILITY LOGS</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              {Object.entries(result.categories || {}).slice(0, 4).map(([key, cat], idx) => (
                <IssueSection key={idx} title={key} issues={cat.issues || []} />
              ))}
            </div>
          </div>

          {/* COMPLIANCE SECTION */}
          {result.compliance && result.compliance.frameworks && (
            <div>
              <div className="section-label" style={{ marginBottom: '24px' }}>COMPLIANCE MAPPING</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '16px' }}>
                {Object.entries(result.compliance.frameworks).map(([key, fw], idx) => (
                  <ComplianceCard key={idx} name={fw.name} score={fw.score} status={fw.status} details={fw.details} />
                ))}
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  )
}

function IssueSection({ title, issues }) {
  const [open, setOpen] = useState(false)
  
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div 
        style={{ 
          background: 'var(--bg-layer2)', 
          borderLeft: '4px solid var(--accent-violet)',
          padding: '16px 24px', 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center',
          cursor: 'pointer',
          clipPath: 'polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 0 100%)'
        }}
        onClick={() => setOpen(!open)}
      >
        <div style={{ fontFamily: 'Orbitron', fontSize: '14px', letterSpacing: '0.1em', color: 'var(--text-primary)', textTransform: 'uppercase' }}>
          {title.replace('_', ' ')}
        </div>
        <div className="hex-badge hex-medium" style={{ padding: '4px 12px' }}>
          {issues.length} ISSUES
        </div>
      </div>
      
      {open && (
        <div className="fade-in-up" style={{ padding: '8px 0 16px 24px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {issues.length === 0 ? (
            <div style={{ fontFamily: 'Share Tech Mono', color: 'var(--accent-neon)', fontSize: '12px' }}>▸ No vulnerabilities detected in this module.</div>
          ) : (
            issues.map((issue, idx) => (
              <div key={idx} className="neural-card" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span className={`hex-badge ${issue.severity === 'CRITICAL' || issue.severity === 'HIGH' ? 'hex-critical' : 'hex-medium'}`} style={{ padding: '2px 8px', fontSize: '9px' }}>
                    {issue.severity || 'WARNING'}
                  </span>
                  <span style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)' }}>{issue.category}</span>
                </div>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: '14px', color: 'var(--text-primary)' }}>
                  {issue.issue || issue.finding || (typeof issue === 'string' ? issue : JSON.stringify(issue))}
                </div>
                {(issue.fix || issue.recommendation) && (
                  <div style={{ marginTop: '8px', padding: '8px 12px', background: 'rgba(57, 255, 20, 0.05)', borderLeft: '2px solid var(--accent-neon)', fontFamily: 'Exo 2', fontSize: '12px', color: 'var(--accent-neon)' }}>
                    🔧 {issue.fix || issue.recommendation}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}

function ComplianceCard({ name, score, status, details }) {
  const [open, setOpen] = useState(false)
  const isCompliant = status === 'COMPLIANT'
  const isPartial = status === 'PARTIAL'
  const color = isCompliant ? 'var(--accent-neon)' : (isPartial ? 'var(--accent-amber)' : 'var(--accent-crimson)')
  
  // Extract findings
  const allFindings = []
  if (details) {
    const subcats = details.categories || details.articles || details.requirements || details.controls || {}
    Object.entries(subcats).forEach(([control, issues]) => {
      if (Array.isArray(issues)) {
        issues.forEach(i => allFindings.push({ control, text: i.finding || i.issue || i }))
      }
    })
  }

  return (
    <div className="neural-card" style={{ borderTop: `2px solid ${color}` }}>
      <div 
        style={{ padding: '20px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
        onClick={() => setOpen(!open)}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ fontFamily: 'Orbitron', fontSize: '14px', color: 'var(--text-primary)', letterSpacing: '0.1em' }}>{name}</div>
          <div style={{ fontFamily: 'Share Tech Mono', fontSize: '12px', color: 'var(--text-secondary)' }}>{allFindings.length} VIOLATIONS DETECTED</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
          <div style={{ fontFamily: 'Share Tech Mono', fontSize: '24px', color: color }}>{score}<span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>/100</span></div>
          <div className="hex-badge" style={{ background: `${color}20`, color: color, border: `1px solid ${color}`, padding: '4px 16px' }}>{status}</div>
        </div>
      </div>
      
      {open && allFindings.length > 0 && (
        <div style={{ padding: '0 24px 24px 24px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ height: '1px', background: 'var(--border-dim)', margin: '0 0 16px 0' }}></div>
          {allFindings.map((finding, idx) => (
            <div key={idx} style={{ display: 'flex', gap: '12px', padding: '8px 12px', background: 'var(--bg-layer2)', borderLeft: `2px solid ${color}` }}>
              <span style={{ color: color }}>▸</span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <span style={{ fontFamily: 'Orbitron', fontSize: '10px', color: 'var(--text-secondary)' }}>{finding.control}</span>
                <span style={{ fontFamily: 'Share Tech Mono', fontSize: '13px', color: 'var(--text-primary)' }}>{typeof finding.text === 'string' ? finding.text : JSON.stringify(finding.text)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
