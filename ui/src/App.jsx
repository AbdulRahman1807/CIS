import { useState, useEffect, useMemo, useRef, Fragment } from 'react'

const ACCENT_LABEL = { PASS: 'PASS', FAIL: 'FAIL', UNKNOWN: 'UNKNOWN' }

const PIPELINE_STAGES = ['TARGET', 'CONNECTOR', 'COLLECTOR', 'RULE ENGINE', 'PRIORITIZER', 'REPORT']

const REDUCED_MOTION = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

function CountUp({ value, duration = 700 }) {
  const [display, setDisplay] = useState(REDUCED_MOTION ? value : 0)
  const frame = useRef(null)

  useEffect(() => {
    if (REDUCED_MOTION) { setDisplay(value); return }
    const start = performance.now()
    const from = 0
    function tick(now) {
      const t = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplay(Math.round(from + (value - from) * eased))
      if (t < 1) frame.current = requestAnimationFrame(tick)
    }
    frame.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame.current)
  }, [value, duration])

  return display
}

// fallback only — used if /api/containers can't be reached (e.g. webui.py
// isn't running, or `docker ps` failed on the backend)
const FALLBACK_TARGETS = ['cis-clean', 'cis-misconfigured', 'cis-broken']

function ScanForm({ defaultTarget, onScanned }) {
  const [target, setTarget] = useState(defaultTarget || '')
  const [scanning, setScanning] = useState(false)
  const [scanError, setScanError] = useState(null)
  const [containers, setContainers] = useState(null) // null = not yet loaded

  useEffect(() => {
    fetch('/api/containers')
      .then((res) => res.json())
      .then((data) => setContainers(Array.isArray(data.containers) ? data.containers : []))
      .catch(() => setContainers([]))
  }, [])

  const targetOptions = containers && containers.length > 0 ? containers : FALLBACK_TARGETS
  const isLive = containers !== null && containers.length > 0

  async function runScan(e) {
    e.preventDefault()
    if (!target.trim()) return
    setScanning(true)
    setScanError(null)
    try {
      const res = await fetch(`/api/scan?target=${encodeURIComponent(target.trim())}`)
      const data = await res.json()
      if (!res.ok || data.error) {
        throw new Error(data.error || `scan failed (HTTP ${res.status})`)
      }
      onScanned(data.report)
    } catch (err) {
      setScanError(err.message || 'scan failed — is webui.py running on :8000?')
    } finally {
      setScanning(false)
    }
  }

  return (
    <form className="scan-form" onSubmit={runScan}>
      <label className="scan-label" htmlFor="scan-target">
        TARGET CONTAINER
        {isLive && <span className="scan-live"> · <i className="dot" style={{ marginRight: 0 }} /> {containers.length} RUNNING</span>}
      </label>
      <div className="scan-row">
        <input
          id="scan-target"
          className="scan-input mono"
          list="known-targets"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="cis-misconfigured"
          disabled={scanning}
          autoComplete="off"
        />
        <datalist id="known-targets">
          {targetOptions.map((t) => <option value={t} key={t} />)}
        </datalist>
        <button className="scan-btn" type="submit" disabled={scanning || !target.trim()}>
          {scanning ? <span className="scan-spinner" aria-hidden="true" /> : null}
          {scanning ? 'AUDITING…' : 'RUN AUDIT'}
        </button>
      </div>
      {scanError && <div className="scan-error mono">✕ {scanError}</div>}
    </form>
  )
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className="copy-btn"
      onClick={() => {
        navigator.clipboard?.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 1200)
      }}
      aria-label="Copy fix command"
    >
      {copied ? 'COPIED' : 'COPY'}
    </button>
  )
}

function EvidenceChain({ finding, fix }) {
  return (
    <tr className="chain-row">
      <td colSpan={5}>
        <div className="chain">
          <div className="chain-node">
            <div className="chain-label">FINDING</div>
            <div className="chain-mono">{finding.rule_id}</div>
            <div className="chain-sub">{finding.title}</div>
            <span className={`badge badge-${finding.status}`}>{finding.status}</span>
          </div>
          <div className="chain-arrow" aria-hidden="true">→</div>
          <div className="chain-node">
            <div className="chain-label">COMMAND</div>
            <pre className="chain-code">{finding.command}</pre>
          </div>
          <div className="chain-arrow" aria-hidden="true">→</div>
          <div className="chain-node">
            <div className="chain-label">{finding.status === 'UNKNOWN' ? 'REASON' : 'OBSERVED EVIDENCE'}</div>
            <pre className="chain-code chain-evidence">{finding.evidence}</pre>
          </div>
          {fix && (
            <>
              <div className="chain-arrow" aria-hidden="true">→</div>
              <div className="chain-node chain-fix">
                <div className="chain-label">REMEDIATION</div>
                <pre className="chain-code">{fix.fix_command}</pre>
                <CopyButton text={fix.fix_command} />
              </div>
            </>
          )}
        </div>
      </td>
    </tr>
  )
}

export function App() {
  const [report, setReport] = useState(null)
  const [error, setError] = useState(false)
  const [loading, setLoading] = useState(true)
  const [selectedRuleId, setSelectedRuleId] = useState(null)

  useEffect(() => {
    fetch('/report.json')
      .then((res) => {
        if (!res.ok) return fetch('/api/report')
        return res
      })
      .then((res) => {
        if (!res.ok) throw new Error()
        return res.json()
      })
      .then((data) => {
        if (!data || Object.keys(data).length === 0 || data.error) {
          throw new Error()
        }
        setReport(data)
        setLoading(false)
      })
      .catch(() => {
        setError(true)
        setLoading(false)
      })
  }, [])

  const fixByRuleId = useMemo(() => {
    if (!report) return {}
    return Object.fromEntries((report.fix_list || []).map((f) => [f.rule_id, f]))
  }, [report])

  const severityByRuleId = useMemo(() => {
    if (!report) return {}
    return Object.fromEntries((report.findings || []).map((f) => [f.rule_id, f.severity_hint]))
  }, [report])

  const uniqueCommandCount = useMemo(() => {
    if (!report) return 0
    return new Set((report.findings || []).map((f) => f.command)).size
  }, [report])

  const shellHeader = (
    <header className="topbar">
      <div className="brand-wrap">
        <div className="brand">CIS AUDIT AGENT</div>
        <div className="tagline">EVIDENCE-GROUNDED · READ-ONLY · DETERMINISTIC</div>
      </div>
      <div className="topbar-meta">
        <span>SYSTEM <b>LINUX / CIS</b></span>
        <span>MODE <b className="accent">READ ONLY</b></span>
        <span>ENGINE <b>DETERMINISTIC</b></span>
        <span><i className="dot" /> OPERATIONAL</span>
      </div>
    </header>
  )

  if (loading) {
    return <div className="mono boot-line"><span className="cursor" />BOOTING AUDIT INTERFACE...</div>
  }

  if (error || !report) {
    return (
      <div className="shell">
        <div className="grain" aria-hidden="true" />
        {shellHeader}
        <div className="report-container">
          <section className="command-center reveal">
            <div className="fallback-line" style={{ padding: '0 0 1.25rem' }}>
              no report found yet — run an audit below, or via the CLI:
              <code className="code-inline" style={{ marginLeft: '0.5rem' }}>python3 -m audit_agent.cli --target &lt;container&gt;</code>
            </div>
            <ScanForm defaultTarget="" onScanned={(r) => { setReport(r); setError(false) }} />
          </section>
        </div>
      </div>
    )
  }

  const { meta, summary, findings, fix_list: fixList } = report
  const total = summary.pass + summary.fail + summary.unknown

  return (
    <div className="shell">
      <div className="grain" aria-hidden="true" />

      {/* SHELL HEADER */}
      {shellHeader}

      <div className="report-container">

        {/* COMMAND CENTER */}
        <section className="command-center reveal">
          <ScanForm defaultTarget={meta.target} onScanned={(r) => { setReport(r); setSelectedRuleId(null) }} />

          <div className="cc-grid">
            <div className="cc-field"><span>TARGET</span><b>{meta.target}</b></div>
            <div className="cc-field"><span>TRANSPORT</span><b>{meta.transport}</b></div>
            <div className="cc-field"><span>USER</span><b>audituser</b></div>
            <div className="cc-field"><span>PRIVILEGE</span><b>NON-ROOT</b></div>
            <div className="cc-field"><span>AUDITED</span><b>{new Date(meta.timestamp).toISOString()}</b></div>
          </div>

          <div className="verdict-counts">
            <div className="vc vc-fail"><div className="vc-num"><CountUp value={summary.fail} /></div><div className="vc-label">FAIL</div></div>
            <div className="vc vc-pass"><div className="vc-num"><CountUp value={summary.pass} /></div><div className="vc-label">PASS</div></div>
            <div className="vc vc-unknown"><div className="vc-num"><CountUp value={summary.unknown} /></div><div className="vc-label">UNKNOWN</div></div>
            <div className="vc"><div className="vc-num"><CountUp value={total} /></div><div className="vc-label">TOTAL</div></div>
          </div>
        </section>

        {/* METRICS */}
        <section className="metrics reveal">
          <div className="metric"><div className="metric-num"><CountUp value={findings.length} /></div><div className="metric-label">RULES</div></div>
          <div className="metric"><div className="metric-num"><CountUp value={uniqueCommandCount} /></div><div className="metric-label">ALLOWLISTED COMMANDS</div></div>
          <div className="metric"><div className="metric-num">0</div><div className="metric-label">MUTATIONS</div></div>
          <div className="metric"><div className="metric-num"><CountUp value={summary.fail} /></div><div className="metric-label">FAILURES</div></div>
        </section>

        {/* PIPELINE */}
        <section className="pipeline reveal">
          <div className="pipeline-title">AUDIT PIPELINE</div>
          <div className="pipeline-strip">
            {PIPELINE_STAGES.map((stage, i) => (
              <div className="pipeline-stage-wrap" key={stage}>
                <div className="pipeline-stage" style={{ animationDelay: `${i * 90}ms` }}>
                  <span className="pipeline-dot" />
                  {stage}
                </div>
                {i < PIPELINE_STAGES.length - 1 && <div className="pipeline-line" style={{ animationDelay: `${i * 90 + 45}ms` }} />}
              </div>
            ))}
          </div>
        </section>

        {/* FINDINGS */}
        <h2>Security Rule Audits ({findings.length})</h2>
        <p className="hint mono">select a row to trace finding → command → evidence → fix</p>
        <table className="findings-table">
          <thead>
            <tr>
              <th style={{ width: '120px' }}>Rule ID</th>
              <th>Title</th>
              <th>Command Run</th>
              <th style={{ width: '90px' }}>Status</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <Fragment key={f.rule_id}>
                <tr
                  className={`finding-row reveal-row ${selectedRuleId === f.rule_id ? 'is-selected' : ''}`}
                  style={{ animationDelay: `${i * 45}ms` }}
                  onClick={() => setSelectedRuleId(selectedRuleId === f.rule_id ? null : f.rule_id)}
                  tabIndex={0}
                  role="button"
                  aria-expanded={selectedRuleId === f.rule_id}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      setSelectedRuleId(selectedRuleId === f.rule_id ? null : f.rule_id)
                    }
                  }}
                >
                  <td className="mono">{f.rule_id}</td>
                  <td>{f.title}</td>
                  <td className="mono">
                    <code className="code-inline">{f.command}</code>
                  </td>
                  <td>
                    <span className={`badge badge-${f.status}`}>{f.status}</span>
                  </td>
                  <td className="mono">
                    <pre className="code-block">{f.evidence}</pre>
                  </td>
                </tr>
                {selectedRuleId === f.rule_id && (
                  <EvidenceChain finding={f} fix={fixByRuleId[f.rule_id]} />
                )}
              </Fragment>
            ))}
          </tbody>
        </table>

        {/* FIX LIST */}
        <h2>Fix List</h2>
        {(!fixList || fixList.length === 0) ? (
          <div className="empty-line">no failures, nothing to fix</div>
        ) : (
          <div>
            {fixList.map((fix, i) => (
              <div
                key={fix.rule_id}
                className={`mono fix-item sev-${(severityByRuleId[fix.rule_id] || 'medium').toLowerCase()} reveal-row`}
                style={{ animationDelay: `${i * 60}ms` }}
              >
                <div className="fix-header">
                  <span className="fix-priority">{String(fix.priority).padStart(2, '0')}</span>
                  <span className="fix-rule">{fix.rule_id}</span>
                  <span className={`sev-badge sev-badge-${(severityByRuleId[fix.rule_id] || 'medium').toLowerCase()}`}>
                    {(severityByRuleId[fix.rule_id] || '').toUpperCase()}
                  </span>
                  <span className="fix-category">{fix.category}</span>
                </div>
                <div className="fix-row">
                  <span className="fix-label">Finding:</span>
                  <span className="fix-value">{fix.finding}</span>
                </div>
                <div className="fix-row">
                  <span className="fix-label">Why it matters:</span>
                  <span className="fix-value">{fix.why_it_matters}</span>
                </div>
                <div className="fix-command-wrapper">
                  <div className="fix-command-label-row">
                    <span className="fix-command-label">Fix Command:</span>
                    <CopyButton text={fix.fix_command} />
                  </div>
                  <pre className="code-block">{fix.fix_command}</pre>
                </div>
              </div>
            ))}
          </div>
        )}

        <footer className="foot mono">
          <span>CIS AUDIT AGENT</span>
          <span>EVIDENCE-GROUNDED · DETERMINISTIC · READ-ONLY</span>
        </footer>
      </div>
    </div>
  )
}

export default App
