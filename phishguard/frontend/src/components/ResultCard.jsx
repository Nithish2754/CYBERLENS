import React from 'react'
import { motion } from 'framer-motion'

export default function ResultCard({ title, icon: Icon, children, accentColor = '#00d4ff' }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="cyber-card p-6 border-l-4"
      style={{ borderLeftColor: accentColor }}
    >
      <div className="flex items-center gap-3 mb-4">
        {Icon && <Icon size={24} style={{ color: accentColor }} />}
        <h3 className="font-mono text-lg font-bold text-cyber-text-primary">{title}</h3>
      </div>
      <div className="text-cyber-text-secondary">{children}</div>
    </motion.div>
  )
}
