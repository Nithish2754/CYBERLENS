import React from 'react'
import { RadialBarChart, RadialBar, PolarAngleAxis, Legend, ResponsiveContainer } from 'recharts'

export default function ThreatGauge({ score = 0, level = 'SAFE' }) {
  // Normalize score to number between 0 and 100 and round for display
  const normalized = Math.max(0, Math.min(100, Number(score) || 0))
  const displayScore = Math.round(normalized)

  const getThreatColor = () => {
    if (typeof level === 'string') {
      const normalized = level.toUpperCase()
      if (['A', 'B', 'SAFE'].includes(normalized)) return '#00ff88'
      if (['C', 'LOW RISK', 'MEDIUM RISK'].includes(normalized)) return '#ffd700'
      if (['D', 'HIGH RISK'].includes(normalized)) return '#f97316'
      if (['F', 'CRITICAL THREAT'].includes(normalized)) return '#ff0040'
    }
    if (displayScore <= 19) return '#00ff88'
    if (displayScore <= 44) return '#ffd700'
    if (displayScore <= 69) return '#f97316'
    return '#ff0040'
  }

  const getGlowClass = () => {
    if (level === 'SAFE') return 'glow-green'
    if (level === 'CRITICAL THREAT') return 'glow-red'
    return 'glow-cyan'
  }

  const data = [{ name: 'Threat Score', value: displayScore, fill: getThreatColor() }]

  return (
    <div className={`flex flex-col items-center justify-center cyber-card p-8 ${getGlowClass()}`}>
      <ResponsiveContainer width={200} height={200}>
        <RadialBarChart data={data} innerRadius="60%" outerRadius="90%">
          <PolarAngleAxis
            type="number"
            domain={[0, 100]}
            angleAxisId={0}
            tick={false}
          />
          <RadialBar
            background
            dataKey="value"
            cornerRadius={10}
            tick={false}
            fill={getThreatColor()}
          />
        </RadialBarChart>
      </ResponsiveContainer>

      <div className="text-center mt-4">
        <div className="text-5xl font-mono font-bold" style={{ color: getThreatColor() }}>
          {displayScore}
        </div>
        <div className="text-cyber-text-secondary font-mono text-sm mt-2">THREAT LEVEL</div>
        <div
          className="mt-3 px-4 py-2 rounded-full font-mono text-sm font-bold inline-block border"
          style={{ color: getThreatColor(), borderColor: getThreatColor() }}
        >
          {level}
        </div>
      </div>
    </div>
  )
}
