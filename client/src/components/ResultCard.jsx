export default function ResultCard({ item, index }) {
  const risk = item.risk_level || 'low'
  const pct  = Math.round((item.confidence || 0) * 100)

  // Classify each signal into a visual category
  function signalType(sig) {
    if (['google_confirmed_phishing','google_confirmed_malware','brand_impersonation','risky_tld'].includes(sig))
      return 'threat'
    if (['non_secure_protocol','google_confirmed_unwanted_software'].includes(sig))
      return 'warning'
    if (['trusted_domain','safe_institutional_tld'].includes(sig))
      return 'safe'
    return 'neutral'
  }

  function signalLabel(sig) {
    return sig.replace(/_/g, ' ')
  }

  const riskLabel = {
    high:   '🔴 HIGH RISK',
    medium: '🟡 MEDIUM RISK',
    low:    '🟢 SAFE',
  }[risk] || '🟢 SAFE'

  const hasSiem = item.siem_alert && item.siem_alert.clicked_users?.length > 0

  return (
    <article
      className={`result-card risk-${risk}`}
      style={{ animationDelay: `${index * 0.08}s` }}
    >
      <div className="card-stripe" />
      <div className="card-body">

        {/* ── URL + Risk Badge ── */}
        <div className="card-header">
          <a
            className="card-url"
            href={item.url}
            target="_blank"
            rel="noopener noreferrer"
          >
            {item.url}
          </a>
          <div className={`risk-badge ${risk}`}>
            {riskLabel}
          </div>
        </div>

        {/* ── Confidence bar ── */}
        <div className={`confidence-row ${risk}`}>
          <span className="confidence-label">Confidence</span>
          <div className="confidence-track">
            <div
              className="confidence-fill"
              style={{ width: `${pct}%` }}
            />
          </div>
          <span className="confidence-pct">{pct}%</span>
        </div>

        {/* ── Signals ── */}
        {item.signals && item.signals.length > 0 && (
          <div className="signals-row">
            {item.signals.map((sig, i) => (
              <span key={i} className={`signal-pill ${signalType(sig)}`}>
                {signalLabel(sig)}
              </span>
            ))}
          </div>
        )}

        {/* ── Decision Summary ── */}
        {item.decision_summary && (
          <div className="decision-box">
            <div className="decision-box-label">Decision Summary</div>
            <div className="decision-box-text">{item.decision_summary}</div>
          </div>
        )}

        {/* ── AI Explanation ── */}
        {item.explanation && item.explanation !== 'AI explanation is temporarily disabled.' && (
          <div className="ai-explanation">
            <div className="ai-label">
              <AIIcon />
              AI Explanation
            </div>
            <div className="ai-text">{item.explanation}</div>
          </div>
        )}

        {/* ── SIEM Alert ── */}
        {hasSiem && (
          <div className="siem-alert">
            <div className="siem-label">⚠️ SIEM Alert — Impacted Users</div>
            <div className="siem-text">
              {item.siem_alert.clicked_users.join(', ')}<br />
              <strong>Action:</strong> {item.siem_alert.recommended_action}
            </div>
          </div>
        )}

      </div>
    </article>
  )
}

function AIIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2a4 4 0 014 4v1h1a3 3 0 013 3v6a3 3 0 01-3 3H7a3 3 0 01-3-3V10a3 3 0 013-3h1V6a4 4 0 014-4z"/>
      <circle cx="9" cy="13" r="1" fill="currentColor" stroke="none"/>
      <circle cx="15" cy="13" r="1" fill="currentColor" stroke="none"/>
    </svg>
  )
}
