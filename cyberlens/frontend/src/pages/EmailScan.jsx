import React, { useState } from 'react'
import axios from 'axios'
import { motion } from 'framer-motion'
import { Mail, AlertTriangle, CheckCircle, AlertCircle, ExternalLink } from 'lucide-react'
import ThreatGauge from '../components/ThreatGauge'
import ResultCard from '../components/ResultCard'
import IndicatorList from '../components/IndicatorList'
import ScanHistory from '../components/ScanHistory'

const API_BASE = 'http://127.0.0.1:8000/api'

export default function EmailScan() {
  const [emailText, setEmailText] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState(() => {
    const saved = localStorage.getItem('emailHistory')
    return saved ? JSON.parse(saved) : []
  })

  const analyzeEmail = async () => {
    if (!emailText.trim()) return

    setLoading(true)
    try {
      const response = await axios.post(`${API_BASE}/scan/email`, { email_text: emailText })
      const data = response.data

      setResult(data)

      // Save to history
      const historyItem = {
        url: `Email: ${data.metadata.subject || 'Unknown'}`,
        threat_level: data.threat_level,
        timestamp: new Date().toLocaleTimeString(),
        verdict: data.verdict,
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

  const handleHistorySelect = (item) => {
    setEmailText('')
  }

  const clearHistory = () => {
    setHistory([])
    localStorage.removeItem('emailHistory')
  }

  const getVerdictColor = (verdict) => {
    if (verdict === 'Safe') return '#00ff88'
    if (verdict === 'Suspicious') return '#ffd700'
    return '#ff0040'
  }

  const getVerdictIcon = (verdict) => {
    if (verdict === 'Safe') return CheckCircle
    if (verdict === 'Suspicious') return AlertTriangle
    return AlertCircle
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
            <Mail className="text-cyber-accent-cyan" />
            <span className="text-gradient">&gt; EMAIL_PHISH_ANALYZER</span>
          </h1>
          <p className="text-cyber-text-secondary font-mono">
            Paste suspicious email content for deep analysis
          </p>
        </motion.div>

        {/* Input Section */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 20 }} className="mb-8">
          <div className="cyber-card p-6 space-y-4">
            <label className="block font-mono text-xs font-bold text-cyber-accent-cyan uppercase tracking-widest">
              Email Content
            </label>
            <textarea
              value={emailText}
              onChange={(e) => setEmailText(e.target.value)}
              placeholder="Paste your suspicious email content here..."
              disabled={loading}
              className="cyber-input"
            />
            <div className="flex justify-between items-center">
              <span className="font-mono text-xs text-cyber-text-secondary">
                {emailText.length} characters
              </span>
              <button
                onClick={analyzeEmail}
                disabled={loading || !emailText.trim()}
                className="cyber-button"
              >
                {loading ? 'ANALYZING...' : 'ANALYZE THREAT'}
              </button>
            </div>
            {loading && <div className="scanning-bar" />}
          </div>
        </motion.div>

        {/* Results */}
        {result && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8 mb-12">
            {/* Top Stats Row */}
            <div className="grid md:grid-cols-3 gap-6">
              {/* Verdict Badge */}
              <motion.div
                initial={{ scale: 0.8, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                className="cyber-card p-6 flex flex-col items-center justify-center"
              >
                {React.createElement(getVerdictIcon(result.verdict), {
                  size: 48,
                  style: { color: getVerdictColor(result.verdict) },
                  className: 'mb-4',
                })}
                <div
                  className="px-4 py-2 rounded-full font-mono text-sm font-bold border"
                  style={{
                    color: getVerdictColor(result.verdict),
                    borderColor: getVerdictColor(result.verdict),
                  }}
                >
                  {result.verdict.toUpperCase()}
                </div>
              </motion.div>

              {/* Threat Gauge */}
              <ThreatGauge score={result.threat_score} level={result.threat_level} />

              {/* Metadata */}
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                className="cyber-card p-6"
              >
                <h3 className="font-mono text-sm font-bold text-cyber-accent-cyan mb-4">METADATA</h3>
                <div className="space-y-3 font-mono text-sm">
                  <div>
                    <span className="text-cyber-text-secondary text-xs block">FROM:</span>
                    <span className="text-cyber-text-primary truncate">{result.metadata.sender}</span>
                  </div>
                  <div>
                    <span className="text-cyber-text-secondary text-xs block">SUBJECT:</span>
                    <span className="text-cyber-text-primary truncate">{result.metadata.subject}</span>
                  </div>
                  <div className="flex gap-6 pt-2">
                    <div>
                      <span className="text-cyber-text-secondary text-xs">URLs: </span>
                      <span className="text-cyber-text-primary font-bold">{result.metadata.url_count}</span>
                    </div>
                    <div>
                      <span className="text-cyber-text-secondary text-xs">Words: </span>
                      <span className="text-cyber-text-primary font-bold">{result.metadata.word_count}</span>
                    </div>
                  </div>
                </div>
              </motion.div>
            </div>

            {/* AI Summary */}
            <ResultCard
              title="AI THREAT SUMMARY"
              icon={Mail}
              accentColor="#00d4ff"
            >
              <p className="text-cyber-text-secondary font-mono leading-relaxed">
                {result.summary}
              </p>
            </ResultCard>

            {/* Phishing Indicators */}
            <ResultCard
              title="PHISHING INDICATORS"
              icon={AlertTriangle}
              accentColor="#ff0040"
            >
              <IndicatorList indicators={result.indicators} />
            </ResultCard>

            {/* Recommended Action */}
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              className="cyber-card p-6 border-l-4"
              style={{
                borderLeftColor: result.verdict === 'Phishing' ? '#ff0040' : '#ffd700',
              }}
            >
              <h3 className="font-mono text-lg font-bold mb-3 flex items-center gap-2">
                <AlertCircle
                  size={24}
                  style={{
                    color: result.verdict === 'Phishing' ? '#ff0040' : '#ffd700',
                  }}
                />
                RECOMMENDED ACTION
              </h3>
              <p className="font-mono text-cyber-text-secondary text-lg">
                {result.recommended_action}
              </p>
            </motion.div>

            {/* Extracted URLs */}
            {result.extracted_urls && result.extracted_urls.length > 0 && (
              <ResultCard
                title="EXTRACTED URLS"
                icon={ExternalLink}
                accentColor="#00ff88"
              >
                <div className="overflow-x-auto">
                  <table className="w-full font-mono text-sm">
                    <thead>
                      <tr className="border-b border-cyber-border">
                        <th className="text-left py-2 text-cyber-text-secondary">URL</th>
                        <th className="text-center py-2 text-cyber-text-secondary">Malicious</th>
                        <th className="text-center py-2 text-cyber-text-secondary">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.extracted_urls.map((item, idx) => (
                        <tr key={idx} className="border-b border-cyber-border/50">
                          <td className="py-2 text-cyber-text-secondary truncate pr-2">
                            {item.url}
                          </td>
                          <td className="text-center py-2">{item.malicious}</td>
                          <td className="text-center py-2">
                            <span
                              className="px-2 py-1 rounded text-xs font-bold"
                              style={{
                                color: item.malicious > 0 ? '#ff0040' : '#00ff88',
                                borderColor: item.malicious > 0 ? '#ff0040' : '#00ff88',
                                border: '1px solid',
                              }}
                            >
                              {item.malicious > 0 ? 'DANGEROUS' : 'CLEAN'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
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
