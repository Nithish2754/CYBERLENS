import React, { useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldCheck, ShieldOff, Zap, Search, Link2, ArrowRight,
  CheckCircle2, AlertTriangle, Globe, Eye, Star, FileText,
  ChevronDown, ChevronUp, Trophy, Activity, TrendingUp, ShieldAlert
} from 'lucide-react'
import ScanInput from '../components/ScanInput'

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

// ─── helpers ────────────────────────────────────────────────────────────────

const gradeColor = (g) => {
  if (g === 'A+' || g === 'A') return '#00ff88'
  if (g === 'B')               return '#84cc16'
  if (g === 'C')               return '#ffd700'
  if (g === 'D')               return '#f97316'
  return '#ff0040'
}

const scoreColor = (s) => {
  if (s >= 80) return '#00ff88'
  if (s >= 60) return '#84cc16'
  if (s >= 40) return '#ffd700'
  if (s >= 20) return '#f97316'
  return '#ff0040'
}

const severityStyle = (sev) => {
  const map = {
    CRITICAL: 'bg-[#ff0040]/10 border-[#ff0040] text-[#ff0040]',
    HIGH:     'bg-[#f97316]/10 border-[#f97316] text-[#f97316]',
    MEDIUM:   'bg-[#ffd700]/10 border-[#ffd700] text-[#ffd700]',
    LOW:      'bg-[#00ff88]/10 border-[#00ff88] text-[#00ff88]',
    INFO:     'bg-[#00d4ff]/10 border-[#00d4ff] text-[#00d4ff]',
  }
  return map[sev] ?? map.LOW
}

// Arc / dial ring ─────────────────────────────────────────────────────────────
function ScoreDial({ score, size = 120, stroke = 10 }) {
  const r = (size - stroke) / 2
  const circ = 2 * Math.PI * r
  const pct = Math.max(0, Math.min(100, score ?? 0))
  const dash = (pct / 100) * circ
  const color = scoreColor(pct)
  return (
    <svg width={size} height={size} className="rotate-[-90deg]">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke="#1e293b" strokeWidth={stroke} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none"
        stroke={color} strokeWidth={stroke}
        strokeDasharray={`${dash} ${circ}`}
        strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 1s ease' }} />
    </svg>
  )
}

// Mini horizontal bar ─────────────────────────────────────────────────────────
function ScoreBar({ score, color }) {
  return (
    <div className="h-1.5 rounded-full bg-[#1e293b] overflow-hidden">
      <div
        className="h-full rounded-full transition-all duration-1000"
        style={{ width: `${score ?? 0}%`, background: color ?? scoreColor(score) }}
      />
    </div>
  )
}

// Category score card ─────────────────────────────────────────────────────────
function CategoryCard({ icon: Icon, label, score, weight, color, onClick, active }) {
  const c = color ?? scoreColor(score ?? 0)
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-xl border p-4 transition-all duration-300
        ${active
          ? 'border-opacity-100 bg-[#0d1117]'
          : 'border-[#21262d] bg-[#0d1117] hover:border-opacity-60'
        }`}
      style={{ borderColor: active ? c : undefined }}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Icon size={15} style={{ color: c }} />
          <span className="font-mono text-xs uppercase tracking-widest text-[#8b949e]">{label}</span>
        </div>
        <span className="font-mono text-[10px] text-[#8b949e]">{Math.round(weight * 100)}%</span>
      </div>
      <div className="font-mono text-2xl font-bold mb-2" style={{ color: c }}>
        {score ?? 0}<span className="text-sm text-[#8b949e]">/100</span>
      </div>
      <ScoreBar score={score} color={c} />
    </button>
  )
}

// Issue card ─────────────────────────────────────────────────────────────────
function IssueCard({ issue, idx, sectionKey }) {
  const [open, setOpen] = useState(false)
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: idx * 0.04 }}
      className="rounded-xl border border-[#21262d] bg-[#07111f] overflow-hidden"
    >
      <button
        className="w-full text-left p-4"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2 flex-1">
            <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-widest ${severityStyle(issue.severity)}`}>
              {issue.severity}
            </span>
            <span className="text-[10px] font-mono text-[#8b949e] uppercase tracking-widest">{issue.category}</span>
          </div>
          {open ? <ChevronUp size={14} className="text-[#8b949e] shrink-0 mt-0.5" /> : <ChevronDown size={14} className="text-[#8b949e] shrink-0 mt-0.5" />}
        </div>
        <p className="mt-2 font-mono text-sm text-[#c9d1d9] leading-relaxed">{issue.issue}</p>
      </button>
      <AnimatePresence>
        {open && issue.fix && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="border-t border-[#21262d] bg-[#0d1117] px-4 py-3"
          >
            <div className="font-mono text-[10px] uppercase tracking-widest text-[#8b949e] mb-1">HOW TO FIX:</div>
            <p className="font-mono text-sm text-[#8b949e] leading-relaxed">{issue.fix}</p>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

// Section panel ───────────────────────────────────────────────────────────────
function AuditSection({ section }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-mono text-xs uppercase tracking-[0.2em] text-[#8b949e]">
          {section.title}
        </h3>
        <span className="font-mono text-xs text-[#8b949e]">{section.issues.length} issue{section.issues.length !== 1 ? 's' : ''}</span>
      </div>
      {section.issues.length > 0 ? (
        <div className="space-y-3">
          {section.issues.map((issue, idx) => (
            <IssueCard key={`${section.key}-${idx}`} issue={issue} idx={idx} sectionKey={section.key} />
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-[#21262d] bg-[#07111f] p-4 font-mono text-sm text-[#8b949e]">
          ✅ No issues found in this category.
        </div>
      )}
    </div>
  )
}

// ─── Compliance helpers ─────────────────────────────────────────────────────

const FRAMEWORK_DESCRIPTIONS = {
  "NIST_CSF": "NIST Cybersecurity Framework — US government standard for managing cybersecurity risk across 5 functions: Identify, Protect, Detect, Respond, Recover.",
  "GDPR": "General Data Protection Regulation — EU law requiring organizations to protect personal data and privacy of EU citizens.",
  "PCI_DSS": "Payment Card Industry Data Security Standard — required for any website handling credit/debit card transactions.",
  "ISO_27001": "ISO/IEC 27001 — International standard for information security management systems (ISMS).",
  "CIS_CONTROLS": "CIS Controls v8 — Prioritized set of cybersecurity best practices developed by the Center for Internet Security."
}

// FIX 3 — use actual fix text from the issue object directly
function FixRecommendation({ issue }) {
  const fixText = (issue && issue.fix) ? issue.fix : 'Review and remediate per framework guidelines'
  return (
    <div style={{
      background: '#00ff8808',
      border: '1px solid #00ff8830',
      borderRadius: '6px',
      padding: '8px 12px',
      fontSize: '12px',
      color: '#00ff88'
    }}>
      🔧 <strong>Fix:</strong> {fixText}
    </div>
  )
}

// FIX 6 — severity badge colors
const severityColors = {
  CRITICAL: '#ff0040',
  HIGH:     '#f97316',
  MEDIUM:   '#ffd700',
  LOW:      '#84cc16',
  INFO:     '#8b949e',
}

// FIX 7 — context-aware improvement tips based on actual findings
function getImprovementTip(framework, score, findings) {
  const findingTexts = (findings || []).map(f => (f.finding || '').toLowerCase())

  const tips = {
    NIST_CSF: () => {
      if (findingTexts.some(f => f.includes('header')))
        return 'Fix missing security headers first — they map to the NIST Protect function and are quick wins.'
      if (findingTexts.some(f => f.includes('ssl') || f.includes('tls')))
        return 'SSL/TLS issues are high priority for NIST PR.DS (Data Security) control.'
      return 'Focus on the Protect (PR) function — implement security headers, encryption, and access controls.'
    },
    GDPR: () => {
      if (findingTexts.some(f => f.includes('cookie')))
        return 'Cookie security flags are mandatory under GDPR Art.32 — fix Secure, HttpOnly, SameSite flags.'
      if (findingTexts.some(f => f.includes('privacy')))
        return 'Add a Privacy Policy page — GDPR requires clear data processing information for users.'
      return 'Prioritize cookie security and adding a Privacy Policy to meet GDPR Art.25 requirements.'
    },
    PCI_DSS: () => {
      if (findingTexts.some(f => f.includes('ssl') || f.includes('tls')))
        return 'PCI-DSS Req.4 requires strong encryption — fix all SSL/TLS issues immediately if handling payments.'
      return 'If handling card payments, fix all encryption and configuration issues urgently for PCI compliance.'
    },
    ISO_27001: () => {
      if (findingTexts.some(f => f.includes('dkim') || f.includes('spf')))
        return 'DNS email security (SPF/DKIM/DMARC) maps to ISO 27001 A.8.20 Network Security controls.'
      return 'Start with A.8.24 (Cryptography) and A.8.20 (Network Security) — highest impact controls.'
    },
    CIS_CONTROLS: () => {
      if (findingTexts.some(f => f.includes('header')))
        return 'CIS Control 4 (Secure Configuration) covers security headers — fix these for biggest compliance gain.'
      return 'CIS Control 4 (Secure Configuration) is your priority — fix server and application configuration issues.'
    },
  }

  const tipFn = tips[framework]
  return tipFn ? tipFn() : 'Review each finding above and implement the recommended fixes.'
}

function ComplianceFrameworkCard({ framework, data }) {
  const [expanded, setExpanded] = useState(false)

  const statusColor =
    data.status === 'COMPLIANT'     ? '#00ff88' :
    data.status === 'PARTIAL'       ? '#ffd700' : '#ff0040'

  // FIX 3 — store full issue objects so fix text and severity are available
  const getDetailedFindings = () => {
    const details = data.details || {}
    const allFindings = []
    const subcategories =
      details.categories ||
      details.articles ||
      details.requirements ||
      details.controls ||
      {}
    Object.entries(subcategories).forEach(([controlName, issues]) => {
      if (Array.isArray(issues) && issues.length > 0) {
        issues.forEach(issue => {
          allFindings.push({
            control:    controlName,
            finding:    typeof issue === 'string' ? issue : (issue.issue || ''),
            fix:        typeof issue === 'string' ? null  : (issue.fix || null),
            severity:   typeof issue === 'string' ? 'MEDIUM' : (issue.severity || 'MEDIUM'),
            full_issue: issue,
          })
        })
      }
    })
    return allFindings
  }

  const detailedFindings = getDetailedFindings()

  return (
    <div
      style={{
        background: '#0d1117',
        border: `1px solid ${expanded ? statusColor : '#21262d'}`,
        borderRadius: '12px',
        padding: '20px',
        cursor: 'pointer',
        transition: 'all 0.3s ease',
        boxShadow: expanded ? `0 0 15px ${statusColor}25` : 'none'
      }}
      onClick={() => setExpanded(e => !e)}
    >
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '12px', color: '#00d4ff', letterSpacing: '0.1em', marginBottom: '4px' }}>
            {data.name}
          </div>
          <div style={{ fontSize: '11px', color: '#8b949e' }}>
            Version: {data.details?.version || ''}
          </div>
        </div>
        <div style={{
          fontSize: '11px',
          color: statusColor,
          fontFamily: 'JetBrains Mono, monospace',
          transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)',
          transition: 'transform 0.3s'
        }}>▼</div>
      </div>

      {/* Score row */}
      <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <span style={{ fontSize: '24px', fontWeight: 'bold', fontFamily: 'JetBrains Mono, monospace', color: statusColor }}>
          {data.score}
        </span>
        <span style={{ color: '#8b949e', fontSize: '12px' }}>/100</span>
        <span style={{
          background: `${statusColor}20`,
          border: `1px solid ${statusColor}`,
          color: statusColor,
          fontSize: '10px',
          padding: '3px 10px',
          borderRadius: '20px',
          fontFamily: 'JetBrains Mono, monospace',
          marginLeft: 'auto'
        }}>{data.status}</span>
      </div>

      {/* Progress bar */}
      <div style={{ height: '4px', background: '#21262d', borderRadius: '2px', marginTop: '10px' }}>
        <div style={{ height: '100%', width: `${data.score}%`, background: statusColor, borderRadius: '2px', transition: 'width 0.5s ease' }} />
      </div>

      <div style={{ fontSize: '11px', color: '#8b949e', marginTop: '8px' }}>
        {data.non_compliant_findings} finding(s) — click to {expanded ? 'collapse' : 'view details'}
      </div>

      {/* Expanded details */}
      {expanded && (
        <div style={{ marginTop: '20px' }} onClick={e => e.stopPropagation()}>
          {/* Framework description */}
          <div style={{
            background: '#161b22',
            border: '1px solid #21262d',
            borderRadius: '8px',
            padding: '12px',
            marginBottom: '16px',
            fontSize: '12px',
            color: '#8b949e',
            lineHeight: '1.6'
          }}>
            ℹ {FRAMEWORK_DESCRIPTIONS[framework] || data.name}
          </div>

          {detailedFindings.length === 0 ? (
            <div style={{ textAlign: 'center', color: '#00ff88', fontFamily: 'JetBrains Mono, monospace', fontSize: '13px', padding: '20px' }}>
              ✓ No violations found for this framework
            </div>
          ) : (
            <div>
              <div style={{ fontSize: '11px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.1em', marginBottom: '12px' }}>
                VIOLATIONS FOUND ({detailedFindings.length})
              </div>
              {detailedFindings.map((item, idx) => {
                const sev = item.severity || 'MEDIUM'
                const sevColor = severityColors[sev] || '#8b949e'
                const borderColor = sev === 'CRITICAL' ? '#ff0040' : sev === 'HIGH' ? '#f97316' : '#21262d'
                return (
                  <div key={idx} style={{
                    background: '#161b22',
                    border: `1px solid ${borderColor}40`,
                    borderLeft: `3px solid ${sevColor}`,
                    borderRadius: '8px',
                    padding: '14px',
                    marginBottom: '10px'
                  }}>
                    {/* Control name */}
                    <div style={{ fontSize: '10px', color: '#ffd700', fontFamily: 'JetBrains Mono, monospace', marginBottom: '6px', letterSpacing: '0.05em' }}>
                      📋 {item.control}
                    </div>
                    {/* FIX 6 — severity badge */}
                    <span style={{
                      background: `${sevColor}20`,
                      border: `1px solid ${sevColor}`,
                      color: sevColor,
                      fontSize: '9px',
                      padding: '2px 8px',
                      borderRadius: '10px',
                      fontFamily: 'JetBrains Mono, monospace',
                      marginBottom: '6px',
                      display: 'inline-block',
                    }}>
                      {sev}
                    </span>
                    <div style={{ fontSize: '13px', color: '#e6edf3', margin: '6px 0 10px', lineHeight: '1.5' }}>
                      ⚠ {item.finding}
                    </div>
                    {/* FIX 3 — pass full issue object for real fix text */}
                    <FixRecommendation issue={item} />
                  </div>
                )
              })}
            </div>
          )}

          {/* Improvement tip */}
          <div style={{
            background: '#00d4ff08',
            border: '1px solid #00d4ff30',
            borderRadius: '8px',
            padding: '12px',
            marginTop: '12px',
            fontSize: '12px',
            color: '#8b949e'
          }}>
            💡 <strong style={{ color: '#00d4ff' }}>To improve {data.name.split(' ')[0]} compliance:</strong>{' '}
            {/* FIX 7 — pass findings for context-aware tip */}
            {getImprovementTip(framework, data.score, detailedFindings)}
          </div>
        </div>
      )}
    </div>
  )
}

function ComplianceSection({ complianceData }) {
  if (!complianceData) return null
  const { overall_compliance_score, frameworks, summary } = complianceData
  const ocs = overall_compliance_score ?? 0
  const ocsColor = ocs >= 70 ? '#00ff88' : ocs >= 40 ? '#ffd700' : '#ff0040'

  return (
    <div className="cyber-card p-6 space-y-6 mt-8">
      {/* Section header */}
      <div className="border-b border-[#21262d] pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="font-mono text-lg font-bold text-white flex items-center gap-2">
            <ShieldCheck className="text-[#00ff88]" size={18} />
            COMPLIANCE ASSESSMENTS &amp; STANDARDS
          </h2>
          <p className="text-xs text-[#8b949e] font-mono mt-0.5">
            Click any framework card to view detailed violations and fix recommendations.
          </p>
        </div>
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl px-6 py-3 flex items-center gap-4">
          <div className="text-right">
            <div className="font-mono text-[10px] text-[#8b949e] uppercase tracking-wider">Overall Compliance Score</div>
            <div className="font-mono text-sm text-[#8b949e]">Mapped against 5 global frameworks</div>
          </div>
          <div className="font-mono text-3xl font-bold" style={{ color: ocsColor }}>{ocs}%</div>
        </div>
      </div>

      {/* Expandable framework cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        {Object.entries(frameworks || {}).map(([key, fw]) => (
          <ComplianceFrameworkCard key={key} framework={key} data={fw} />
        ))}
      </div>

      {/* Summary table */}
      {summary && summary.length > 0 && (
        <div style={{ marginTop: '24px' }}>
          <div style={{ fontSize: '11px', color: '#00d4ff', fontFamily: 'JetBrains Mono, monospace', letterSpacing: '0.1em', marginBottom: '12px' }}>
            COMPLIANCE SUMMARY
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #21262d' }}>
                {['Framework', 'Score', 'Grade', 'Status', 'Findings'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '8px 12px', fontSize: '11px', color: '#8b949e', fontFamily: 'JetBrains Mono, monospace' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {summary.map((item, idx) => {
                const color = item.status === 'COMPLIANT' ? '#00ff88' : item.status === 'PARTIAL' ? '#ffd700' : '#ff0040'
                return (
                  <tr key={idx} style={{ borderBottom: '1px solid #21262d20' }}>
                    <td style={{ padding: '10px 12px', fontSize: '12px', color: '#e6edf3' }}>{item.framework}</td>
                    <td style={{ padding: '10px 12px', fontSize: '12px', color, fontFamily: 'JetBrains Mono, monospace' }}>{item.score}/100</td>
                    <td style={{ padding: '10px 12px', fontSize: '12px', color, fontFamily: 'JetBrains Mono, monospace' }}>{item.grade}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{ background: `${color}20`, border: `1px solid ${color}`, color, fontSize: '10px', padding: '3px 10px', borderRadius: '20px', fontFamily: 'JetBrains Mono, monospace' }}>
                        {item.status}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px', fontSize: '12px', color: '#8b949e' }}>{item.non_compliant_findings}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────
export default function WebsiteAudit() {
  const [url, setUrl]           = useState('')
  const [loading, setLoading]   = useState(false)
  const [stepIndex, setStepIndex] = useState(0)
  const [result, setResult]     = useState(null)
  const [error, setError]       = useState(null)
  const [activeTab, setActiveTab] = useState('ssl_tls')

  // Cycle scan steps while loading
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
      setActiveTab('ssl_tls')
    } catch (err) {
      setError('Could not run the audit. Please verify the backend is running and the URL is reachable.')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  // Category config (order = tab order)
  const categories = useMemo(() => [
    { key: 'ssl_tls',    label: 'SSL/TLS Security',         icon: ShieldCheck, weight: 0.20, color: '#00d4ff' },
    { key: 'headers',    label: 'Security Headers',         icon: FileText,    weight: 0.20, color: '#a78bfa' },
    { key: 'dns',        label: 'DNS Security',             icon: Globe,       weight: 0.10, color: '#34d399' },
    { key: 'reputation', label: 'Domain Reputation',        icon: Star,        weight: 0.15, color: '#fbbf24' },
    { key: 'vulns',      label: 'Vulnerability Assessment', icon: AlertTriangle, weight: 0.15, color: '#60a5fa' },
    { key: 'threat',     label: 'Threat Intelligence',      icon: Search,      weight: 0.10, color: '#f472b6' },
    { key: 'cookies',    label: 'Cookie Security',          icon: ShieldCheck, weight: 0.05, color: '#fb923c' },
    { key: 'cve_analysis', label: 'CVE Analysis',            icon: ShieldAlert,  weight: 0.05, color: '#f43f5e' },
  ], [])

  const activeCat = useMemo(() => categories.find(c => c.key === activeTab), [categories, activeTab])

  const activeSection = useMemo(() => {
    if (!result || !result.categories) return null
    const raw = result.categories[activeTab]
    return {
      key: activeTab,
      title: activeCat?.label ?? activeTab,
      issues: raw?.issues ?? [],
      passed: raw?.passed ?? [],
    }
  }, [result, activeTab, activeCat])

  const allPassed = useMemo(() => {
    if (!result || !result.categories) return []
    return categories.flatMap(c => (result.categories[c.key]?.passed ?? []))
  }, [result, categories])

  const issueCounts = useMemo(() => {
    if (!result || !result.categories) return {}
    const counts = {}
    categories.forEach(c => {
      counts[c.key] = result.categories[c.key]?.issues?.length ?? 0
    })
    return counts
  }, [result, categories])

  return (
    <div className="min-h-screen pt-24 pb-20 bg-[#030712] matrix-bg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 space-y-10">

        {/* ── Header ── */}
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-[#21262d] bg-[#0d1117] text-[#8b949e] font-mono text-xs tracking-widest mb-4">
            <Globe size={13} className="text-[#00d4ff]" />
            WEBSITE SECURITY & QUALITY ASSESSMENT
          </div>
          <h1 className="font-mono text-3xl md:text-5xl font-bold text-[#e6edf3] leading-tight">
            7-Category <span className="text-gradient">Website Audit</span>
          </h1>
          <p className="mt-3 max-w-2xl text-[#8b949e] font-mono text-sm leading-relaxed">
            SSL/TLS · Headers · DNS · Reputation · Vulnerabilities · Threat Intel · Cookies —
            all weighted into a single professional security score out of 100.
          </p>
        </motion.div>

        {/* ── Input ── */}
        <ScanInput url={url} setUrl={setUrl} onScan={performAudit} loading={loading} placeholder="https://example.com" />

        {/* ── Loading ── */}
        <AnimatePresence>
          {loading && (
            <motion.div
              initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
              className="cyber-card p-6"
            >
              <div className="flex items-center gap-4 mb-4">
                <div className="spinner shrink-0" />
                <div className="font-mono text-sm text-[#00d4ff]">{scanSteps[stepIndex]}</div>
              </div>
              <div className="h-1 rounded-full bg-[#1e293b] overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-[#00d4ff] to-[#7c3aed] transition-all duration-700"
                  style={{ width: `${((stepIndex + 1) / scanSteps.length) * 100}%` }}
                />
              </div>
              <div className="mt-3 font-mono text-xs text-[#8b949e]">
                Step {stepIndex + 1} of {scanSteps.length} — this may take 30–60 s for large sites
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── Error ── */}
        {error && (
          <div className="px-4 py-3 rounded-xl border border-[#ff0040] bg-[#ff0040]/10 text-[#ff0040] font-mono text-sm">
            {error}
          </div>
        )}

        {/* ── Results ── */}
        {result && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">

            {/* Overall score + grade */}
            <div className="grid md:grid-cols-[auto_1fr] gap-6 cyber-card p-6">
              <div className="flex flex-col items-center justify-center gap-2 relative">
                <ScoreDial score={result.overall_score} size={140} stroke={12} />
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="font-mono text-3xl font-bold" style={{ color: scoreColor(result.overall_score) }}>
                    {result.overall_score}
                  </span>
                  <span className="font-mono text-xs text-[#8b949e]">/ 100</span>
                </div>
              </div>
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <div className="font-mono text-4xl font-bold" style={{ color: gradeColor(result.grade) }}>
                    {result.grade}
                  </div>
                  <div>
                    <div className="font-mono text-base font-semibold text-[#e6edf3]">Overall Health Score</div>
                    <div className="font-mono text-xs text-[#8b949e]">
                      {result.url?.replace(/^https?:\/\//, '')}
                    </div>
                  </div>
                </div>
                {/* Issue summary pills */}
                <div className="flex flex-wrap gap-2 pt-1">
                  {[
                    { label: 'Critical', count: result.critical_issues, color: '#ff0040' },
                    { label: 'High',     count: result.high_issues,     color: '#f97316' },
                    { label: 'Medium',   count: result.medium_issues,   color: '#ffd700' },
                    { label: 'Low',      count: result.low_issues,      color: '#00ff88' },
                  ].map(({ label, count, color }) => (
                    <div key={label} className="flex items-center gap-1.5 px-3 py-1 rounded-full border font-mono text-xs"
                      style={{ borderColor: color, color, background: `${color}10` }}>
                      <span className="font-bold">{count}</span>
                      <span className="text-[10px] uppercase tracking-widest">{label}</span>
                    </div>
                  ))}
                  <div className="flex items-center gap-1.5 px-3 py-1 rounded-full border border-[#21262d] font-mono text-xs text-[#8b949e]">
                    {result.total_issues} total issues
                  </div>
                </div>
                {/* AI summary */}
                {result.ai_summary && (
                  <div className="mt-2 rounded-xl border border-[#21262d] bg-[#07111f] p-4">
                    <div className="font-mono text-[10px] uppercase tracking-widest text-[#8b949e] mb-2 flex items-center gap-1.5">
                      <Activity size={11} /> AI EXECUTIVE SUMMARY
                    </div>
                    <p className="font-mono text-sm text-[#c9d1d9] leading-relaxed">{result.ai_summary}</p>
                  </div>
                )}
              </div>
            </div>

            {/* ── Weighted score breakdown ── */}
            <div>
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp size={14} className="text-[#00d4ff]" />
                <h2 className="font-mono text-xs uppercase tracking-[0.2em] text-[#8b949e]">
                  Score Breakdown — click a category to view its issues
                </h2>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-3">
                {categories.map(cat => (
                  <CategoryCard
                    key={cat.key}
                    icon={cat.icon}
                    label={cat.label}
                    score={result.categories?.[cat.key]?.score ?? 0}
                    weight={cat.weight}
                    color={cat.color}
                    active={activeTab === cat.key}
                    onClick={() => setActiveTab(cat.key)}
                  />
                ))}
              </div>
            </div>

            {/* ── Two-column: issues + passed ── */}
            <div className="grid xl:grid-cols-[1fr_380px] gap-6">

              {/* Issues panel */}
              <div className="cyber-card p-6 space-y-4">
                <div className="flex items-center gap-3 pb-3 border-b border-[#21262d]">
                  {activeCat && <activeCat.icon size={16} style={{ color: activeCat.color }} />}
                  <h2 className="font-mono text-sm uppercase tracking-[0.2em] text-[#e6edf3]">
                    {activeCat?.label ?? activeTab} Issues
                  </h2>
                  {activeCat?.weight > 0 && (
                    <span className="ml-auto font-mono text-[10px] text-[#8b949e] border border-[#21262d] rounded-full px-2 py-0.5">
                      {Math.round(activeCat.weight * 100)}% weight
                    </span>
                  )}
                </div>

                {/* Threat Intelligence Sources Grid */}
                {activeTab === 'threat' && (() => {
                  const threatData = result.threat_intelligence || {}
                  const reputationData = result.domain_reputation || {}
                  const otx = threatData.otx || {}
                  const urlhaus = threatData.urlhaus || {}
                  return (
                    <div className="mb-6 grid grid-cols-2 md:grid-cols-3 gap-4">
                      {/* VirusTotal Card */}
                      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-4 flex flex-col justify-between">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-xs text-[#8b949e] uppercase tracking-wider">VirusTotal</span>
                          {((threatData.details?.vt_malicious > 0) || (reputationData.details?.vt_malicious > 0)) ? (
                            <span className="text-[#ff0040] text-xs font-bold font-mono">⚠ FLAGGED</span>
                          ) : (
                            <span className="text-[#00ff88] text-xs font-bold font-mono">✓ CLEAN</span>
                          )}
                        </div>
                        <div className="font-mono text-lg font-bold text-white">
                          {((threatData.details?.vt_malicious) || (reputationData.details?.vt_malicious)) || 0} detections
                        </div>
                        <span className="font-mono text-[10px] text-[#8b949e] mt-1">Multi-engine scan</span>
                      </div>

                      {/* Safe Browsing Card */}
                      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-4 flex flex-col justify-between">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-xs text-[#8b949e] uppercase tracking-wider">Google Safe Browsing</span>
                          {result.all_issues?.some(i => i.issue?.toLowerCase().includes('google safe browsing')) ? (
                            <span className="text-[#ff0040] text-xs font-bold font-mono">⚠ FLAGGED</span>
                          ) : (
                            <span className="text-[#00ff88] text-xs font-bold font-mono">✓ CLEAN</span>
                          )}
                        </div>
                        <div className="font-mono text-lg font-bold text-white">
                          {result.all_issues?.some(i => i.issue?.toLowerCase().includes('google safe browsing')) ? "Malicious Site" : "Clean"}
                        </div>
                        <span className="font-mono text-[10px] text-[#8b949e] mt-1">Google Blacklist</span>
                      </div>

                      {/* IPQualityScore Card */}
                      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-4 flex flex-col justify-between">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-xs text-[#8b949e] uppercase tracking-wider">IPQS Risk Score</span>
                          {threatData.details?.ipqs_risk > 70 ? (
                            <span className="text-[#ff0040] text-xs font-bold font-mono">⚠ HIGH RISK</span>
                          ) : (
                            <span className="text-[#00ff88] text-xs font-bold font-mono">✓ CLEAN</span>
                          )}
                        </div>
                        <div className="font-mono text-lg font-bold text-white">
                          {threatData.details?.ipqs_risk !== undefined ? `${threatData.details.ipqs_risk}/100` : "--"}
                        </div>
                        <span className="font-mono text-[10px] text-[#8b949e] mt-1">IP & Domain Quality</span>
                      </div>

                      {/* PhishTank Card */}
                      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-4 flex flex-col justify-between">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-xs text-[#8b949e] uppercase tracking-wider">PhishTank</span>
                          {reputationData.details?.phishtank?.in_database ? (
                            <span className="text-[#ff0040] text-xs font-bold font-mono">⚠ LISTED</span>
                          ) : (
                            <span className="text-[#00ff88] text-xs font-bold font-mono">✓ CLEAN</span>
                          )}
                        </div>
                        <div className="font-mono text-lg font-bold text-white">
                          {reputationData.details?.phishtank?.in_database ? "Phishing Database" : "Not Listed"}
                        </div>
                        <span className="font-mono text-[10px] text-[#8b949e] mt-1">Community database</span>
                      </div>

                      {/* AlienVault OTX Card */}
                      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-4 flex flex-col justify-between">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-xs text-[#8b949e] uppercase tracking-wider">AlienVault OTX</span>
                          {otx.available === false ? (
                            <span className="text-[#8b949e] text-xs font-bold font-mono">N/A</span>
                          ) : (otx.details?.pulse_count > 0 || otx.details?.url_pulse_count > 0) ? (
                            <span className="text-[#ff0040] text-xs font-bold font-mono">⚠ FLAGGED</span>
                          ) : (
                            <span className="text-[#00ff88] text-xs font-bold font-mono">✓ CLEAN</span>
                          )}
                        </div>
                        <div className="font-mono text-lg font-bold text-white">
                          {otx.available === false ? "No API Key" : `${otx.details?.pulse_count || 0} pulses`}
                        </div>
                        <span className="font-mono text-[10px] text-[#8b949e] mt-1">
                          {otx.available === false ? "OTX feed disabled" : `URL pulses: ${otx.details?.url_pulse_count || 0}`}
                        </span>
                      </div>

                      {/* URLHaus Card */}
                      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-4 flex flex-col justify-between">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-xs text-[#8b949e] uppercase tracking-wider">URLHaus</span>
                          {urlhaus.available === false ? (
                            <span className="text-[#8b949e] text-xs font-bold font-mono">N/A</span>
                          ) : (urlhaus.issues?.length > 0) ? (
                            <span className="text-[#ff0040] text-xs font-bold font-mono">⚠ MALWARE</span>
                          ) : (
                            <span className="text-[#00ff88] text-xs font-bold font-mono">✓ CLEAN</span>
                          )}
                        </div>
                        <div className="font-mono text-lg font-bold text-white">
                          {urlhaus.available === false ? "Scan Failed" : (urlhaus.issues?.length > 0 ? "Listed" : "Not Listed")}
                        </div>
                        <span className="font-mono text-[10px] text-[#8b949e] mt-1">Abuse.ch Malware Feed</span>
                      </div>
                    </div>
                  )
                })()}

                {/* CVE Analysis custom render or Fallback AuditSection */}
                {activeTab === 'cve_analysis' ? (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-mono text-xs text-[#8b949e] uppercase tracking-wider">Detected Technologies & CVEs</span>
                      <span className="font-mono text-xs text-[#8b949e]">
                        {result.cve_analysis?.total_cves_found || 0} CVEs found
                      </span>
                    </div>
                    
                    {(!result.cve_analysis?.technologies || result.cve_analysis.technologies.length === 0) ? (
                      <div className="rounded-xl border border-[#21262d] bg-[#07111f] p-6 font-mono text-sm text-[#8b949e] text-center">
                        ✓ No specific technology versions detected. No known vulnerabilities mapped.
                      </div>
                    ) : (
                      <div className="grid gap-6">
                        {result.cve_analysis.technologies.map((tech, tIdx) => (
                          <div key={tIdx} className="rounded-xl border border-[#21262d] bg-[#0d1117] overflow-hidden">
                            {/* Tech Header Card */}
                            <div className="bg-[#161b22] px-6 py-4 border-b border-[#21262d] flex items-center justify-between flex-wrap gap-4">
                              <div>
                                <h3 className="font-mono text-lg font-bold text-white flex items-center gap-2">
                                  <span className="text-[#00d4ff]">&gt;</span> {tech.name}
                                </h3>
                                <p className="text-[#8b949e] font-mono text-xs mt-0.5">
                                  Detected from: <span className="text-white">{tech.detected_from}</span>
                                </p>
                              </div>
                              <div className="bg-[#21262d] px-3 py-1 rounded-full font-mono text-xs text-white">
                                Version: <span className="font-bold text-[#00ff88]">{tech.version}</span>
                              </div>
                            </div>

                            {/* CVE List below Tech */}
                            <div className="p-6 space-y-4">
                              {(!tech.cves || tech.cves.length === 0) ? (
                                <p className="font-mono text-xs text-[#8b949e]">✓ No matched CVEs found for this version.</p>
                              ) : (
                                <div className="grid gap-4">
                                  {tech.cves.map((cve, cIdx) => {
                                    let badgeColor = "bg-[#ff0040]/10 border-[#ff0040] text-[#ff0040]";
                                    const score = cve.cvss_score;
                                    if (score >= 9.0) {
                                      badgeColor = "bg-[#ff0040]/10 border-[#ff0040] text-[#ff0040]";
                                    } else if (score >= 7.0) {
                                      badgeColor = "bg-[#f97316]/10 border-[#f97316] text-[#f97316]";
                                    } else if (score >= 4.0) {
                                      badgeColor = "bg-[#ffd700]/10 border-[#ffd700] text-[#ffd700]";
                                    } else {
                                      badgeColor = "bg-[#00d4ff]/10 border-[#00d4ff] text-[#00d4ff]";
                                    }

                                    return (
                                      <div key={cIdx} className="rounded-lg border border-[#21262d] bg-[#07111f] p-4 flex flex-col md:flex-row md:items-start gap-4">
                                        <div className="shrink-0 flex md:flex-col gap-2">
                                          <span className={`inline-flex items-center justify-center rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-widest ${badgeColor}`}>
                                            {cve.cve_id}
                                          </span>
                                          <span className="font-mono text-xs text-white bg-[#21262d] px-2 py-0.5 rounded text-center">
                                            Score: {score}
                                          </span>
                                        </div>
                                        <div className="flex-1 space-y-2">
                                          <p className="font-mono text-xs text-[#c9d1d9] leading-relaxed">
                                            {cve.description}
                                          </p>
                                          <a 
                                            href={cve.url} 
                                            target="_blank" 
                                            rel="noopener noreferrer" 
                                            className="inline-flex items-center gap-1 font-mono text-xs text-[#00d4ff] hover:underline"
                                          >
                                            View NVD Detail <ArrowRight size={10} />
                                          </a>
                                        </div>
                                      </div>
                                    )
                                  })}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  activeSection && <AuditSection section={activeSection} />
                )}
              </div>

              {/* Right: passed checks + broken links table */}
              <div className="space-y-5">

                {/* Passed checks */}
                <div className="cyber-card p-5">
                  <div className="flex items-center gap-2 mb-4">
                    <Trophy size={14} className="text-[#00ff88]" />
                    <h3 className="font-mono text-xs uppercase tracking-[0.2em] text-[#8b949e]">
                      Passed Checks ({allPassed.length})
                    </h3>
                  </div>
                  {allPassed.length > 0 ? (
                    <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                      {allPassed.map((item, idx) => (
                        <div key={`${item}-${idx}`}
                          className="flex items-start gap-2.5 p-2.5 rounded-lg bg-[#0d1117] border border-[#1e293b]">
                          <CheckCircle2 size={13} className="text-[#00ff88] mt-0.5 shrink-0" />
                          <span className="font-mono text-xs text-[#8b949e] leading-relaxed">{item}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="font-mono text-xs text-[#8b949e]">No passed checks recorded.</p>
                  )}
                </div>

                {/* Per-category issue count summary */}
                <div className="cyber-card p-5">
                  <div className="flex items-center gap-2 mb-4">
                    <AlertTriangle size={14} className="text-[#ffd700]" />
                    <h3 className="font-mono text-xs uppercase tracking-[0.2em] text-[#8b949e]">
                      Issues by Category
                    </h3>
                  </div>
                  <div className="space-y-3">
                    {categories.map(cat => {
                      const cnt = issueCounts[cat.key] ?? 0
                      const sc = result.categories?.[cat.key]?.score ?? 0
                      return (
                        <button
                          key={cat.key}
                          onClick={() => setActiveTab(cat.key)}
                          className="w-full flex items-center gap-3 group"
                        >
                          <cat.icon size={13} style={{ color: cat.color }} className="shrink-0" />
                          <span className="font-mono text-xs text-[#8b949e] w-28 text-left truncate group-hover:text-[#c9d1d9] transition-colors">
                            {cat.label}
                          </span>
                          <div className="flex-1">
                            <ScoreBar score={sc} color={cat.color} />
                          </div>
                          <span className="font-mono text-xs shrink-0" style={{ color: cat.color }}>
                            {sc}
                          </span>
                          {cnt > 0 && (
                            <span className="font-mono text-[10px] text-[#ff0040] shrink-0">
                              {cnt}✗
                            </span>
                          )}
                        </button>
                      )
                    })}
                  </div>
                </div>

              </div>
            </div>

            {/* ── Scoring weight legend ── */}
            <div className="cyber-card p-5">
              <div className="flex items-center gap-2 mb-4">
                <ShieldCheck size={13} className="text-[#00d4ff]" />
                <h3 className="font-mono text-xs uppercase tracking-[0.2em] text-[#8b949e]">
                  Scoring Weight Reference
                </h3>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-8 gap-3">
                {categories.filter(c => c.weight > 0).map(cat => (
                  <div key={cat.key} className="rounded-lg border border-[#21262d] bg-[#07111f] p-3 text-center">
                    <cat.icon size={16} className="mx-auto mb-1" style={{ color: cat.color }} />
                    <div className="font-mono text-[10px] text-[#8b949e] uppercase tracking-widest">{cat.label}</div>
                    <div className="font-mono text-base font-bold mt-0.5" style={{ color: cat.color }}>
                      {Math.round(cat.weight * 100)}%
                    </div>
                  </div>
                ))}
              </div>
              <p className="mt-3 font-mono text-[10px] text-[#8b949e]">
                Overall Score = SSL/TLS×20% + Headers×20% + DNS×10% + Reputation×15% + Vulns×15% + Threat Intel×10% + Cookies×5% + CVE×5%
              </p>
            </div>

            {/* ── Compliance Frameworks Section ── */}
            {result.compliance_mapping && (
              <ComplianceSection complianceData={result.compliance_mapping} />
            )}
          </motion.div>
        )}

        {/* ── Empty state ── */}
        {!loading && !result && !error && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="text-center py-20"
          >
            <Globe size={48} className="mx-auto text-[#21262d] mb-4" />
            <p className="font-mono text-sm text-[#8b949e]">
              Enter a URL above to run a full 7-category security & quality audit.
            </p>
            <div className="mt-6 flex flex-wrap justify-center gap-2">
              {['SSL/TLS', 'Headers', 'DNS', 'Reputation', 'Vulnerabilities', 'Threat Intel', 'Cookies'].map(tag => (
                <span key={tag} className="px-3 py-1 rounded-full border border-[#21262d] font-mono text-[10px] text-[#8b949e]">
                  {tag}
                </span>
              ))}
            </div>
          </motion.div>
        )}

      </div>
    </div>
  )
}
