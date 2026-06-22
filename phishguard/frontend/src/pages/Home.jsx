import React from 'react'
import { Link } from 'react-router-dom'
import { Globe, Mail, Brain, CheckCircle, Zap, Shield } from 'lucide-react'
import { motion } from 'framer-motion'

export default function Home() {
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
      },
    },
  }

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.6 },
    },
  }

  return (
    <div className="matrix-bg min-h-screen pt-20 pb-20">
      <motion.div
        initial="hidden"
        animate="visible"
        variants={containerVariants}
        className="max-w-6xl mx-auto px-6"
      >
        {/* Header Badge */}
        <motion.div variants={itemVariants} className="text-center mb-12">
          <div className="inline-block px-4 py-2 border border-cyber-accent-cyan rounded text-cyber-accent-cyan font-mono text-xs font-bold tracking-widest">
            [ THREAT INTELLIGENCE PLATFORM v1.0 ]
          </div>
        </motion.div>

        {/* Main Heading */}
        <motion.div variants={itemVariants} className="text-center mb-8">
          <h1 className="font-mono text-6xl font-bold leading-tight mb-4">
            <span className="text-cyber-text-primary">DETECT.</span>
            <br />
            <span className="text-gradient">ANALYZE.</span>
            <br />
            <span className="text-cyber-text-primary">PROTECT.</span>
          </h1>
          <p className="text-cyber-text-secondary max-w-2xl mx-auto text-lg font-mono">
            Real-time phishing detection powered by VirusTotal, Google Safe Browsing & Gemini AI
          </p>
        </motion.div>

        {/* Scan Buttons */}
        <motion.div variants={itemVariants} className="flex gap-6 justify-center mb-12">
          <Link
            to="/url"
            className="cyber-button flex items-center gap-3 px-8 py-4 text-lg hover:glow-cyan"
          >
            <Globe size={24} />
            SCAN URL
          </Link>
          <Link
            to="/email"
            className="cyber-button flex items-center gap-3 px-8 py-4 text-lg"
            style={{ borderColor: '#7c3aed', color: '#7c3aed' }}
          >
            <Mail size={24} />
            ANALYZE EMAIL
          </Link>
        </motion.div>

        {/* Stats Bar */}
        <motion.div
          variants={itemVariants}
          className="flex justify-center gap-12 mb-20 font-mono text-cyber-text-secondary text-sm"
        >
          <div className="flex items-center gap-2">
            <CheckCircle size={16} className="text-cyber-accent-green" />
            90+ Security Engines
          </div>
          <div className="text-cyber-border">|</div>
          <div className="flex items-center gap-2">
            <Zap size={16} className="text-cyber-accent-cyan" />
            AI-Powered Analysis
          </div>
          <div className="text-cyber-border">|</div>
          <div className="flex items-center gap-2">
            <Shield size={16} className="text-cyber-accent-purple" />
            Real-time Detection
          </div>
        </motion.div>

        {/* Feature Cards */}
        <motion.div
          variants={itemVariants}
          className="grid md:grid-cols-3 gap-6 mb-20"
        >
          {/* URL Scanner */}
          <motion.div
            whileHover={{ borderColor: '#00d4ff', boxShadow: '0 0 20px rgba(0, 212, 255, 0.15)' }}
            className="cyber-card p-8 border transition"
          >
            <Globe size={32} className="text-cyber-accent-cyan mb-4" />
            <h3 className="font-mono text-lg font-bold mb-2">URL THREAT SCAN</h3>
            <p className="text-cyber-text-secondary text-sm mb-4 font-mono">
              Submit any URL for instant analysis across 90+ security engines with AI-powered
              verdict
            </p>
            <Link to="/url" className="text-cyber-accent-cyan hover:text-cyber-accent-purple transition font-mono text-sm font-bold">
              Launch Scanner →
            </Link>
          </motion.div>

          {/* Email Analyzer */}
          <motion.div
            whileHover={{ borderColor: '#7c3aed', boxShadow: '0 0 20px rgba(124, 58, 237, 0.15)' }}
            className="cyber-card p-8 border transition"
          >
            <Mail size={32} style={{ color: '#7c3aed' }} className="mb-4" />
            <h3 className="font-mono text-lg font-bold mb-2">EMAIL PHISH DETECT</h3>
            <p className="text-cyber-text-secondary text-sm mb-4 font-mono">
              Paste suspicious email content for deep phishing pattern analysis and threat
              scoring
            </p>
            <Link to="/email" className="transition font-mono text-sm font-bold" style={{ color: '#7c3aed' }}>
              Launch Analyzer →
            </Link>
          </motion.div>

          {/* AI Analysis */}
          <motion.div
            whileHover={{ borderColor: '#00ff88', boxShadow: '0 0 20px rgba(0, 255, 136, 0.15)' }}
            className="cyber-card p-8 border transition"
          >
            <Brain size={32} className="text-cyber-accent-green mb-4" />
            <h3 className="font-mono text-lg font-bold mb-2">GEMINI AI ENGINE</h3>
            <p className="text-cyber-text-secondary text-sm mb-4 font-mono">
              Advanced natural language analysis identifies social engineering tactics and
              manipulation patterns
            </p>
            <div className="text-cyber-accent-green font-mono text-sm font-bold">Active ✓</div>
          </motion.div>
        </motion.div>

        {/* Footer */}
        <motion.div variants={itemVariants} className="text-center text-cyber-text-secondary font-mono text-sm">
          <p>PhishGuard | Built with FastAPI + React + Gemini AI</p>
        </motion.div>
      </motion.div>
    </div>
  )
}
