import React from 'react'
import { Loader } from 'lucide-react'

export default function ScanInput({ url, setUrl, onScan, loading = false, placeholder = 'Enter URL...' }) {
  return (
    <div className="cyber-card p-6 space-y-4">
      <label className="block font-mono text-xs font-bold text-cyber-accent-cyan uppercase tracking-widest">
        Target URL
      </label>
      <div className="flex gap-3">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && !loading && onScan()}
          placeholder={placeholder}
          disabled={loading}
          className="cyber-input flex-1"
        />
        <button
          onClick={onScan}
          disabled={loading || !url.trim()}
          className="cyber-button flex items-center gap-2 whitespace-nowrap"
        >
          {loading ? (
            <>
              <Loader className="w-4 h-4 animate-spin" />
              SCANNING...
            </>
          ) : (
            'SCAN'
          )}
        </button>
      </div>
      {loading && <div className="scanning-bar" />}
    </div>
  )
}
