import { useState, useEffect } from 'react'

export function App() {
  const [report, setReport] = useState(null)
  const [error, setError] = useState(false)
  const [loading, setLoading] = useState(true)

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

  if (loading) {
    return <div className="mono" style={{ padding: '2.5rem' }}>Loading report...</div>
  }

  if (error || !report) {
    return <div className="fallback-line">no report found — run the CLI first.</div>
  }

  const { meta, summary, findings, fix_list: fixList } = report
  const total = summary.pass + summary.fail + summary.unknown

  return (
    <div className="report-container">
      {/* 1. VERDICT LINE */}
      <div className="verdict-line">
        {meta.target} ({new Date(meta.timestamp).toISOString()}) via {meta.transport} — {summary.fail} FAILED / {summary.pass} PASSED / {summary.unknown} UNKNOWN out of {total}
      </div>

      {/* 2. FINDINGS */}
      <h2>Findings</h2>
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
          {findings.map((f) => (
            <tr key={f.rule_id}>
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
          ))}
        </tbody>
      </table>

      {/* 3. FIX LIST */}
      <h2>Fix List</h2>
      {(!fixList || fixList.length === 0) ? (
        <div className="empty-line">no failures, nothing to fix</div>
      ) : (
        <div>
          {fixList.map((fix) => (
            <div key={fix.rule_id} className="mono fix-item">
              <div className="fix-header">
                <span className="fix-rule">{fix.rule_id}</span>
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
                <span className="fix-command-label">Fix Command:</span>
                <pre className="code-block">{fix.fix_command}</pre>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default App
