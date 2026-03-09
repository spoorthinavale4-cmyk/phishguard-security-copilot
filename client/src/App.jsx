import { useState } from 'react'
import ResultCard from './components/ResultCard.jsx'

const API_URL = import.meta.env.VITE_API_URL
if (!API_URL) console.error('VITE_API_URL is not set! Set it in your Vercel environment variables.')


export default function App() {
  const [emailText, setEmailText] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)

  async function handleAnalyze() {
    if (!emailText.trim()) return
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const res = await fetch(`${API_URL}/analyze-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_text: emailText }),
      })

      if (!res.ok) {
        throw new Error(`Server returned ${res.status}`)
      }

      const data = await res.json()
      setResults(data)
    } catch (err) {
      setError(err.message || 'Failed to connect to the API. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  function handleKeyDown(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') handleAnalyze()
  }

  return (
    <div className="app">
      {/* ── Header ── */}
      <header className="header">
        <div className="header-icon">
          <svg viewBox="0 0 52 52" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path
              d="M26 4L8 12V26C8 36.5 16 44.5 26 48C36 44.5 44 36.5 44 26V12L26 4Z"
              fill="rgba(0,225,200,0.12)"
              stroke="#00e1c8"
              strokeWidth="1.5"
            />
            <path
              d="M20 26l4.5 4.5 8-8"
              stroke="#00e1c8"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>

        <div className="header-text">
          <h1>PhishGuard</h1>
          <p>Security Copilot</p>
        </div>

        <div className="status-badge">
          <span className="status-dot" />
          AI Active
        </div>
      </header>

      {/* ── Email Input ── */}
      <section className="input-section">
        <label className="input-label" htmlFor="emailInput">
          Paste Email Content
        </label>
        <textarea
          id="emailInput"
          className="email-textarea"
          placeholder={"Paste the full email body here — headers, links, and all.\nPhishGuard will extract and analyze every URL it finds.\n\n(Ctrl+Enter to analyze)"}
          value={emailText}
          onChange={e => setEmailText(e.target.value)}
          onKeyDown={handleKeyDown}
          spellCheck={false}
        />
        <div className="input-footer">
          <span className="char-hint">
            {emailText.length > 0 ? `${emailText.length} characters` : 'Ctrl + Enter to analyze'}
          </span>
          <button
            id="analyzeBtn"
            className="analyze-btn"
            onClick={handleAnalyze}
            disabled={loading || !emailText.trim()}
          >
            {loading ? (
              <>
                <SpinnerIcon /> Scanning…
              </>
            ) : (
              <>
                <ScanIcon /> Analyze Email
              </>
            )}
          </button>
        </div>
      </section>

      {/* ── Scanning State ── */}
      {loading && (
        <div className="scanning-wrapper">
          <span className="scanning-text">🔍 Scanning URLs for threats…</span>
          <div className="scan-bar">
            <div className="scan-bar-fill" />
          </div>
        </div>
      )}

      {/* ── Error ── */}
      {error && (
        <div className="error-banner">
          <span>⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {/* ── Results ── */}
      {results && (
        <>
          {results.analysis.length === 0 ? (
            <div className="no-urls">
              <span>🔎</span>
              No URLs were found in the email.
            </div>
          ) : (
            <>
              <div className="results-header">
                <h2>Analysis Results</h2>
                <span className="results-count">{results.analysis.length} URL{results.analysis.length !== 1 ? 's' : ''} scanned</span>
              </div>

              {results.analysis.map((item, i) => (
                <ResultCard key={i} item={item} index={i} />
              ))}
            </>
          )}
        </>
      )}

      {/* ── Footer ── */}
      <footer className="footer">
        PhishGuard Security Copilot &nbsp;·&nbsp; ML + Google Safe Browsing + LLM &nbsp;·&nbsp; Built for SOC teams
      </footer>
    </div>
  )
}

function ScanIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 7V5a2 2 0 012-2h2M17 3h2a2 2 0 012 2v2M21 17v2a2 2 0 01-2 2h-2M7 21H5a2 2 0 01-2-2v-2"/>
      <circle cx="12" cy="12" r="3"/>
    </svg>
  )
}

function SpinnerIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ animation: 'spin 0.8s linear infinite' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      <path d="M21 12a9 9 0 11-6.219-8.56"/>
    </svg>
  )
}
