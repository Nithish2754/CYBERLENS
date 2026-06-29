import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield } from 'lucide-react'

export default function Navbar() {
  const location = useLocation()

  const isActive = (path) => location.pathname === path

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 cyber-border bg-cyber-bg-primary/95 backdrop-blur-sm border-b border-cyber-border">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-2 group">
          <Shield className="w-6 h-6 text-cyber-accent-cyan group-hover:text-cyber-accent-purple transition" />
          <span className="font-mono text-lg font-bold">
            <span className="text-gradient">CYBER</span>
            <span className="text-cyber-accent-cyan">LENS</span>
          </span>
        </Link>

        {/* Navigation Links */}
        <div className="flex items-center gap-8">
          <Link
            to="/"
            className={`font-mono text-sm transition ${
              isActive('/') 
                ? 'text-cyber-accent-cyan border-b-2 border-cyber-accent-cyan' 
                : 'text-cyber-text-secondary hover:text-cyber-accent-cyan'
            }`}
          >
            [~/ home]
          </Link>
          <Link
            to="/url"
            className={`font-mono text-sm transition ${
              isActive('/url') 
                ? 'text-cyber-accent-cyan border-b-2 border-cyber-accent-cyan' 
                : 'text-cyber-text-secondary hover:text-cyber-accent-cyan'
            }`}
          >
            [~/ scan-url]
          </Link>
          <Link
            to="/email"
            className={`font-mono text-sm transition ${
              isActive('/email') 
                ? 'text-cyber-accent-cyan border-b-2 border-cyber-accent-cyan' 
                : 'text-cyber-text-secondary hover:text-cyber-accent-cyan'
            }`}
          >
            [~/ scan-email]
          </Link>
          <Link
            to="/audit"
            className={`font-mono text-sm transition ${
              isActive('/audit') 
                ? 'text-cyber-accent-cyan border-b-2 border-cyber-accent-cyan' 
                : 'text-cyber-text-secondary hover:text-cyber-accent-cyan'
            }`}
          >
            [~/ audit]
          </Link>
        </div>

        {/* Status indicator */}
        <div className="flex items-center gap-2 text-cyber-accent-green text-sm font-mono">
          <span className="w-2 h-2 bg-cyber-accent-green rounded-full animate-pulse"></span>
          SYSTEM ONLINE
        </div>
      </div>
    </nav>
  )
}
