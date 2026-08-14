import { useEffect, useState } from 'react'

// Reads /report.json — the exact JSON audit_agent/report.py's build_report()
// produces (WORKPLAN.md §2.2/§2.3 contracts), copied/written to
// ui/public/report.json by cli.py after each run.
//
// This component is a placeholder. If an already-built UI is dropped in
// instead, it only needs to keep this same fetch contract: GET /report.json
// -> { findings: [...], fix_list: [...], unknowns: [...], summary: {...} }.
function App() {
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetch('/report.json')
      .then((res) => {
        if (!res.ok) throw new Error(`report.json: ${res.status}`)
        return res.json()
      })
      .then(setReport)
      .catch((err) => setError(err.message))
  }, [])

  if (error) return <p>No report loaded yet ({error}). Run cli.py first.</p>
  if (!report) return <p>Loading report…</p>

  return (
    <main>
      <h1>CIS Audit Report</h1>
      <pre>{JSON.stringify(report, null, 2)}</pre>
    </main>
  )
}

export default App
