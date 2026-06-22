import React, { useState } from 'react'
import axios from 'axios'
import { motion } from 'framer-motion'
import { Globe, AlertTriangle, CheckCircle, BarChart3, AlertOctagon, Image as ImageIcon } from 'lucide-react'
import ScanInput from '../components/ScanInput'
import ThreatGauge from '../components/ThreatGauge'
import ResultCard from '../components/ResultCard'
import IndicatorList from '../components/IndicatorList'
import ScanHistory from '../components/ScanHistory'

const API_BASE = 'http://127.0.0.1:8000/api'

export default function URLScan() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState(() => {
    const saved = localStorage.getItem('urlHistory')
    return saved ? JSON.parse(saved) : []
  })

  const scanURL = async () => {
    if (!url.trim()) return

    setLoading(true)
    try {
      const response = await axios.post(`${API_BASE}/scan/url`, { url })
      const data = response.data

      setResult(data)

      // Save to history
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

  const handleHistorySelect = (item) => {
    setUrl(item.url)
  }

  const clearHistory = () => {
    setHistory([])
    localStorage.removeItem('urlHistory')
  }

  return (
    <div className="min-h-screen pt-24 pb-12 bg-cyber-bg-primary">
      <div className="max-w-6xl mx-auto px-6">
        {/* Page Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-12"
        >
          <h1 className="font-mono text-4xl font-bold mb-2 flex items-center gap-3">
            <Globe className="text-cyber-accent-cyan" />
            <span className="text-gradient">&gt; URL_THREAT_SCANNER</span>
          </h1>
          <p className="text-cyber-text-secondary font-mono">
            Analyze any URL against 90+ security engines
          </p>
        </motion.div>

        {/* Scan Input */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 20 }} className="mb-8">
          <ScanInput
            url={url}
            setUrl={setUrl}
            onScan={scanURL}
            loading={loading}
            placeholder="https://suspicious-site.com"
          />
        </motion.div>

        {/* Results */}
        {result && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8 mb-12">
            {/* Threat Score */}
              {/* Critical banner */}
              {result.threat_score >= 70 && (
                <div className="w-full mb-4 p-4 rounded text-white font-bold text-center" style={{ background: '#ff0040', boxShadow: '0 0 12px #ff0040' }}>
                  ⚠ CRITICAL THREAT DETECTED — Do not visit this URL
                </div>
              )}
              <div className="grid md:grid-cols-2 gap-8">
              <div className="flex justify-center">
                <ThreatGauge score={result.threat_score} level={result.threat_level} />
              </div>

              <div className="space-y-4">
                {/* Threat Analysis */}
                <ResultCard title="THREAT ANALYSIS" icon={AlertTriangle} accentColor="#ff0040">
                  <IndicatorList indicators={result.reasons} />
                </ResultCard>
              </div>
            </div>

            {/* Intelligence Sources */}
            <ResultCard title="INTELLIGENCE SOURCES" icon={BarChart3} accentColor="#7c3aed">
              <div className="grid grid-cols-5 gap-4 text-center font-mono text-sm">
                {(() => {
                  const sources = []
                  // VirusTotal
                  const vtFlag = result.virustotal && result.virustotal.total_engines > 0
                  sources.push({
                    name: 'VirusTotal',
                    status: vtFlag ? (result.virustotal.malicious > 0 ? 'flagged' : 'clean') : 'unknown',
                    score: vtFlag ? `${result.virustotal.malicious}/${result.virustotal.total_engines}` : '--'
                  })
                  // Safe Browsing
                  sources.push({
                    name: 'Safe Browsing',
                    status: result.safe_browsing && result.safe_browsing.is_threat ? 'flagged' : 'clean',
                    score: result.safe_browsing && result.safe_browsing.is_threat ? result.safe_browsing.threat_types.join(', ') : '--'
                  })
                  // Pattern AI
                  sources.push({
                    name: 'Pattern AI',
                    status: result.pattern_analysis && result.pattern_analysis.flags_count > 0 ? 'flagged' : 'clean',
                    score: result.pattern_analysis ? `${result.pattern_analysis.pattern_score}` : '--'
                  })
                  // DNS Check
                  sources.push({
                    name: 'DNS Check',
                    status: result.dns_analysis && !result.dns_analysis.resolved ? 'flagged' : (result.dns_analysis && result.dns_analysis.dns_score > 20 ? 'flagged' : 'clean'),
                    score: result.dns_analysis ? `${result.dns_analysis.dns_score}` : '--'
                  })
                  // Domain Analysis
                  sources.push({
                    name: 'Domain Analysis',
                    status: result.domain_analysis && result.domain_analysis.heuristic_score > 20 ? 'flagged' : 'clean',
                    score: result.domain_analysis ? `${result.domain_analysis.heuristic_score}` : '--'
                  })
                  // IPQualityScore
                  const ipqs = result.ipqs || { available: false }
                  let ipqs_status = 'unknown'
                  let ipqs_score = '--'
                  if (ipqs.available === false) {
                    ipqs_status = 'unknown'
                    ipqs_score = 'API unavailable'
                  } else if (ipqs) {
                    const rs = ipqs.risk_score || 0
                    ipqs_status = (ipqs.phishing || ipqs.suspicious || rs > 70) ? 'flagged' : 'clean'
                    ipqs_score = `${rs}/100`
                  }
                  sources.push({
                    name: 'IPQualityScore',
                    status: ipqs_status,
                    score: ipqs_score
                  })
                  // PhishTank
                  const pt = result.phishtank || { available: false }
                  let pt_status = 'unknown'
                  let pt_score = '--'
                  if (pt.available === false) {
                    pt_status = 'unknown'
                    pt_score = 'Unavailable'
                  } else {
                    pt_status = pt.in_database ? 'flagged' : 'clean'
                    pt_score = pt.in_database && pt.phish_id ? `⚠ IN DATABASE (id:${pt.phish_id})` : 'Not listed'
                  }
                  sources.push({ name: 'PhishTank', status: pt_status, score: pt_score })
                  // SSL Certificate
                  const ssl = result.ssl_analysis || { available: false }
                  let ssl_status = 'unknown'
                  let ssl_score = '--'
                  if (ssl.available === false) {
                    ssl_status = 'unknown'
                    ssl_score = 'Check failed'
                  } else {
                    ssl_status = ssl.valid === false ? 'flagged' : 'clean'
                    ssl_score = ssl.flags && ssl.flags.length > 0 ? ssl.flags[0] : `${ssl.ssl_score || '--'}`
                  }
                  sources.push({ name: 'SSL Certificate', status: ssl_status, score: ssl_score })
                  // Redirect Chain
                  sources.push({
                    name: 'Redirect Chain',
                    status: result.redirect_analysis && result.redirect_analysis.redirect_count > 0 && result.redirect_analysis.redirect_score > 20 ? 'flagged' : (result.redirect_analysis ? 'clean' : 'unknown'),
                    score: result.redirect_analysis ? `${result.redirect_analysis.redirect_count}` : '--'
                  })
                  // URLScan
                  const us = result.urlscan || { available: false }
                  let us_status = 'unknown'
                  let us_score = '--'
                  if (us.available === false) {
                    us_status = 'unknown'
                    us_score = 'Unavailable'
                  } else {
                    us_status = us.malicious ? 'flagged' : 'clean'
                    us_score = us.malicious ? 'MALICIOUS' : (us.score !== undefined ? `${us.score}` : 'Clean')
                  }
                  sources.push({ name: 'URLScan.io', status: us_status, score: us_score })

                  // Confidence
                  const available = [
                    !!result.virustotal, !!result.safe_browsing, !!result.pattern_analysis,
                    !!result.dns_analysis, !!result.domain_analysis, !!result.ipqs, !!result.phishtank, !!result.ssl_analysis, !!result.redirect_analysis, !!result.urlscan
                  ].filter(Boolean).length
                  let confidence = 'LOW'
                  if (available >= 5) confidence = 'HIGH'
                  else if (available >= 3) confidence = 'MEDIUM'

                  return (
                    <>
                      {sources.map((s, i) => (
                        <div key={i} className="p-3 bg-cyber-bg-tertiary rounded">
                          <div className="font-bold mb-1">{s.name}</div>
                          <div>
                            {s.status === 'clean' && <CheckCircle className="text-cyber-accent-green inline-block" />}
                            {s.status === 'flagged' && <AlertTriangle className="text-cyber-accent-red inline-block" />}
                            {s.status === 'unknown' && <div className="inline-block text-cyber-text-secondary">—</div>}
                          </div>
                          <div className="text-xs text-cyber-text-secondary mt-2">{s.score}</div>
                        </div>
                      ))}
                      <div className="col-span-5 mt-2 text-center">
                        <div className="font-mono text-xs text-cyber-text-secondary">Detection Confidence</div>
                        <div className="font-bold">{confidence}</div>
                      </div>
                    </>
                  )
                })()}
              </div>
            </ResultCard>

            {/* AI Assessment */}
            <ResultCard
              title="AI ASSESSMENT"
              icon={Globe}
              accentColor="#00d4ff"
            >
              <p className="text-cyber-text-secondary font-mono leading-relaxed">
                {result.ai_explanation}
              </p>
            </ResultCard>

            {/* Detection Breakdown */}
            <ResultCard
              title="DETECTION BREAKDOWN"
              icon={BarChart3}
              accentColor="#7c3aed"
            >
              <div className="grid md:grid-cols-2 gap-6">
                {/* VirusTotal */}
                <div className="bg-cyber-bg-tertiary p-4 rounded">
                  <div className="font-mono text-sm text-cyber-text-secondary mb-3">VirusTotal</div>
                  <div className="text-2xl font-bold mb-3">
                    {result.virustotal.malicious}/{result.virustotal.total_engines}
                  </div>
                  <div className="font-mono text-xs text-cyber-text-secondary mb-3">
                    Malicious engines detected
                  </div>
                  <div className="w-full bg-cyber-bg-secondary rounded h-2">
                    <div
                      className="bg-cyber-accent-red h-2 rounded"
                      style={{
                        width: `${
                          result.virustotal.total_engines > 0
                            ? (result.virustotal.malicious / result.virustotal.total_engines) * 100
                            : 0
                        }%`,
                      }}
                    />
                  </div>
                </div>

                {/* Safe Browsing */}
                <div className="bg-cyber-bg-tertiary p-4 rounded">
                  <div className="font-mono text-sm text-cyber-text-secondary mb-3">Google Safe Browsing</div>
                  <div className="flex items-center gap-3">
                    {result.safe_browsing.is_threat ? (
                      <>
                        <AlertTriangle size={32} className="text-cyber-accent-red" />
                        <div>
                          <div className="font-bold text-cyber-accent-red">THREAT DETECTED</div>
                          <div className="font-mono text-xs text-cyber-text-secondary">
                            {result.safe_browsing.threat_types.join(', ')}
                          </div>
                        </div>
                      </>
                    ) : (
                      <>
                        <CheckCircle size={32} className="text-cyber-accent-green" />
                        <div>
                          <div className="font-bold text-cyber-accent-green">CLEAN</div>
                          <div className="font-mono text-xs text-cyber-text-secondary">No threats detected</div>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            </ResultCard>

            {/* URL Details */}
            <ResultCard title="URL DETAILS" icon={Globe} accentColor="#00ff88">
              <div className="space-y-3 font-mono text-sm">
                <div>
                  <span className="text-cyber-text-secondary">Full URL: </span>
                  <span className="text-cyber-accent-cyan break-all">{result.url}</span>
                </div>
                {result.virustotal.title && (
                  <div>
                    <span className="text-cyber-text-secondary">Title: </span>
                    <span>{result.virustotal.title}</span>
                  </div>
                )}
                <div>
                  <span className="text-cyber-text-secondary">Scanned: </span>
                  <span>{new Date(result.timestamp).toLocaleString()}</span>
                </div>
              </div>
            </ResultCard>

            {/* Pattern Analysis */}
            {result.pattern_analysis && result.pattern_analysis.flags_count > 0 && (
              <ResultCard title="PATTERN ANALYSIS" icon={AlertOctagon} accentColor="#ff6b00">
                <div className="space-y-2 font-mono text-sm">
                  {result.pattern_analysis.flags.map((f, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <AlertOctagon className="text-cyber-accent-red mt-1" />
                      <div>{f}</div>
                    </div>
                  ))}
                </div>
              </ResultCard>
            )}

            {/* URLScan Screenshot */}
            {result.urlscan && result.urlscan.screenshot_url && (
              <ResultCard title="SITE SCREENSHOT" icon={ImageIcon} accentColor="#00d4ff">
                <div className="space-y-3">
                  <img src={result.urlscan.screenshot_url} alt="site screenshot" className="w-full rounded shadow-md" />
                  <div className="text-sm font-mono text-cyber-text-secondary">
                    <a href={result.urlscan.result_url} target="_blank" rel="noreferrer" className="text-cyber-accent-cyan underline">
                      View full URLScan report
                    </a>
                  </div>
                </div>
              </ResultCard>
            )}
          </motion.div>
        )}

        {/* Scan History */}
        <ScanHistory history={history} onSelect={handleHistorySelect} onClear={clearHistory} />
      </div>
    </div>
  )
}
