import React from 'react'
import { motion } from 'framer-motion'
import { Trash2 } from 'lucide-react'

export default function ScanHistory({ history = [], onSelect, onClear }) {
  if (history.length === 0) {
    return (
      <div className="cyber-card p-6 text-center">
        <p className="font-mono text-cyber-text-secondary">No scan history yet</p>
      </div>
    )
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="cyber-card p-6 space-y-4"
    >
      <div className="flex justify-between items-center">
        <h3 className="font-mono text-lg font-bold text-cyber-text-primary">
          &gt; SCAN_HISTORY
        </h3>
        <button
          onClick={onClear}
          className="text-cyber-accent-red hover:text-cyber-accent-orange transition flex items-center gap-1 text-sm"
        >
          <Trash2 size={16} />
          CLEAR
        </button>
      </div>

      <div className="space-y-2">
        {history.slice(0, 5).map((item, idx) => (
          <div
            key={idx}
            onClick={() => onSelect(item)}
            className="p-3 bg-cyber-bg-tertiary rounded border border-cyber-border hover:border-cyber-accent-cyan cursor-pointer transition font-mono text-sm"
          >
            <div className="flex justify-between items-center">
              <span className="text-cyber-text-secondary truncate flex-1">{item.url}</span>
              <span
                className="px-2 py-1 rounded text-xs font-bold ml-2"
                style={{
                  color: item.threat_level === 'SAFE' ? '#00ff88' : '#ff0040',
                  borderColor: item.threat_level === 'SAFE' ? '#00ff88' : '#ff0040',
                  border: '1px solid',
                }}
              >
                {item.threat_level}
              </span>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  )
}
