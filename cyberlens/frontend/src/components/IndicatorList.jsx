import React from 'react'
import { motion } from 'framer-motion'
import { AlertTriangle } from 'lucide-react'

export default function IndicatorList({ indicators = [] }) {
  return (
    <div className="space-y-3">
      {indicators.map((indicator, idx) => (
        <motion.div
          key={idx}
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: idx * 0.1 }}
          className="flex items-start gap-3 p-3 bg-cyber-bg-tertiary rounded border-l-2 border-cyber-accent-orange"
        >
          <AlertTriangle size={18} className="text-cyber-accent-orange flex-shrink-0 mt-0.5" />
          <span className="font-mono text-sm text-cyber-text-secondary">{indicator}</span>
        </motion.div>
      ))}
    </div>
  )
}
