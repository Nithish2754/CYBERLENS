import layatechLogo from "../assets/layatech-logo.png"

export default function Footer() {
  return (
    <footer style={{
      borderTop: "1px solid #21262d",
      background: "#0d1117",
      padding: "24px 40px",
      marginTop: "60px"
    }}>
      <div style={{
        maxWidth: "1200px",
        margin: "0 auto",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "16px"
      }}>

        {/* Left — PhishGuard branding */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span style={{
            fontFamily: "JetBrains Mono",
            fontSize: "14px",
            color: "#00d4ff",
            fontWeight: "bold"
          }}>
            CYBER<span style={{ color: "#e6edf3" }}>LENS</span>
          </span>
          <span style={{ color: "#21262d" }}>|</span>
          <span style={{
            fontFamily: "JetBrains Mono",
            fontSize: "11px",
            color: "#8b949e"
          }}>
            AI-Powered Threat Intelligence Platform
          </span>
        </div>

        {/* Center — Internship credit */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "10px"
        }}>
          <span style={{
            fontSize: "11px",
            color: "#8b949e",
            fontFamily: "JetBrains Mono"
          }}>
            Built during internship at
          </span>
          <div style={{
            background: "white",
            borderRadius: "6px",
            padding: "4px 10px",
            display: "flex",
            alignItems: "center"
          }}>
            <img
              src={layatechLogo}
              alt="Laya Tech"
              style={{
                height: "22px",
                objectFit: "contain",
                opacity: 0.85,
                transition: "opacity 0.2s"
              }}
              onMouseEnter={e => e.target.style.opacity = 1}
              onMouseLeave={e => e.target.style.opacity = 0.85}
            />
          </div>
        </div>

        {/* Right — copyright */}
        <div style={{
          fontFamily: "JetBrains Mono",
          fontSize: "11px",
          color: "#8b949e"
        }}>
          © 2026 CyberLens. All rights reserved.
        </div>

      </div>
    </footer>
  )
}
