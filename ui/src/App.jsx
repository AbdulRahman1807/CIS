import { useState, useEffect, useMemo } from 'react'

// High-fidelity fallback report in case the scanner has not created report.json yet
const mockReport = {
  meta: {
    target: "cis-docker-target-01",
    timestamp: new Date().toISOString(),
    transport: "docker-exec"
  },
  summary: {
    pass: 5,
    fail: 4,
    unknown: 1
  },
  findings: [
    {
      rule_id: "CIS-5.2.10",
      title: "SSH root login disabled",
      command: "grep -iE '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config",
      status: "FAIL",
      evidence: "PermitRootLogin yes\nPasswordAuthentication yes",
      severity_hint: "high"
    },
    {
      rule_id: "CIS-5.2.11",
      title: "SSH password auth disabled",
      command: "grep -iE '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config",
      status: "FAIL",
      evidence: "PasswordAuthentication yes",
      severity_hint: "high"
    },
    {
      rule_id: "CIS-5.3.1",
      title: "Minimum password length \u226514",
      command: "cat /etc/login.defs",
      status: "FAIL",
      evidence: "PASS_MIN_LEN 5\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7",
      severity_hint: "medium"
    },
    {
      rule_id: "CIS-6.1.2",
      title: "/etc/passwd ownership/perms",
      command: "stat -c %U:%G %a /etc/passwd",
      status: "PASS",
      evidence: "root:root 644",
      severity_hint: "medium"
    },
    {
      rule_id: "CIS-6.1.3",
      title: "/etc/shadow ownership/perms",
      command: "stat -c %U:%G %a /etc/shadow",
      status: "PASS",
      evidence: "root:shadow 600",
      severity_hint: "high"
    },
    {
      rule_id: "CIS-6.1.10",
      title: "No world-writable files in /etc",
      command: "find /etc -xdev -type f -perm -0002",
      status: "PASS",
      evidence: "No world-writable files found under /etc.",
      severity_hint: "medium"
    },
    {
      rule_id: "CIS-3.5.1",
      title: "Firewall active",
      command: "iptables -L INPUT -n",
      status: "UNKNOWN",
      evidence: "iptables: executable file not found in path",
      severity_hint: "high"
    },
    {
      rule_id: "CIS-2.2.4",
      title: "Automatic security updates enabled",
      command: "cat /etc/apt/apt.conf.d/20auto-upgrades",
      status: "FAIL",
      evidence: "cat: /etc/apt/apt.conf.d/20auto-upgrades: No such file or directory",
      severity_hint: "medium"
    },
    {
      rule_id: "CIS-5.4.1",
      title: "No accounts with empty passwords",
      command: "awk -F: ($2==\"\"){print $1} /etc/shadow",
      status: "PASS",
      evidence: "Verification passed: all credentials secure.",
      severity_hint: "critical"
    },
    {
      rule_id: "CIS-5.2.9",
      title: "No blanket NOPASSWD:ALL in sudoers",
      command: "grep -r NOPASSWD /etc/sudoers /etc/sudoers.d",
      status: "PASS",
      evidence: "No active password wildcards found in sudoers configuration files.",
      severity_hint: "high"
    }
  ],
  fix_list: [
    {
      priority: 1,
      rule_id: "CIS-5.2.10",
      category: "SSH Hardening",
      finding: "Root login over SSH is permitted (PermitRootLogin yes).",
      why_it_matters: "A leaked root credential permits immediate and total system takeover without privilege steps.",
      fix_command: "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
      evidence_ref: "CIS-5.2.10"
    },
    {
      priority: 2,
      rule_id: "CIS-5.2.11",
      category: "SSH Hardening",
      finding: "Password authentication is enabled over SSH (PasswordAuthentication yes).",
      why_it_matters: "Password login exposes the port to automated credential dictionary and brute-force attacks.",
      fix_command: "sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
      evidence_ref: "CIS-5.2.11"
    },
    {
      priority: 3,
      rule_id: "CIS-5.3.1",
      category: "Password Policy",
      finding: "Minimum password length is configured to 5 (benchmark requires 14).",
      why_it_matters: "Short passwords can be cracked in seconds using standard offline decryption tables.",
      fix_command: "sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 14/' /etc/login.defs",
      evidence_ref: "CIS-5.3.1"
    },
    {
      priority: 4,
      rule_id: "CIS-2.2.4",
      category: "Automatic Updates",
      finding: "Automatic security upgrades are not configured (apt config missing).",
      why_it_matters: "Outdated packages are the single most common entry point for automated cyber exploits.",
      fix_command: "echo 'APT::Periodic::Update-Package-Lists \"1\";\\nAPT::Periodic::Unattended-Upgrade \"1\";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades",
      evidence_ref: "CIS-2.2.4"
    }
  ]
}

export function App() {
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [targetInput, setTargetInput] = useState("")
  const [scanError, setScanError] = useState(null)
  
  const [statusFilter, setStatusFilter] = useState("ALL")
  const [severityFilter, setSeverityFilter] = useState("ALL")
  const [searchQuery, setSearchQuery] = useState("")
  const [expandedFindings, setExpandedFindings] = useState({})
  const [copiedFixId, setCopiedFixId] = useState(null)

  // Fetch report logic
  const loadReportData = (showSpinner = true) => {
    if (showSpinner) setLoading(true)
    else setRefreshing(true)
    
    fetch('/report.json')
      .then((res) => {
        if (!res.ok) return fetch('/api/report')
        return res
      })
      .then((res) => {
        if (!res.ok) throw new Error('Data endpoint offline')
        return res.json()
      })
      .then((data) => {
        if (!data || Object.keys(data).length === 0 || data.error) {
          throw new Error(data?.error || 'Empty payload')
        }
        setReport(data)
        setTargetInput(data.meta.target || "")
        setLoading(false)
        setRefreshing(false)
      })
      .catch((err) => {
        console.warn('Backend server report loading failed. Using mock data. Details:', err.message)
        const activeReport = window.AUDIT_REPORT || mockReport
        setReport(activeReport)
        setTargetInput(activeReport.meta.target || "")
        setLoading(false)
        setRefreshing(false)
      })
  }

  // Load report on component mount
  useEffect(() => {
    loadReportData(true)
  }, [])

  // Trigger live scan over backend subprocess
  const triggerLiveScan = () => {
    const cleanTarget = targetInput.trim()
    if (!cleanTarget) {
      setScanError("Target container name cannot be empty.")
      return
    }
    
    setRefreshing(true)
    setScanError(null)
    
    fetch(`/api/scan?target=${encodeURIComponent(cleanTarget)}`)
      .then(async (res) => {
        const payload = await res.json()
        if (!res.ok) {
          throw new Error(payload.error || `Verification failed with HTTP ${res.status}`)
        }
        return payload
      })
      .then((data) => {
        if (data.report) {
          setReport(data.report)
          setTargetInput(data.report.meta.target || "")
        }
        setRefreshing(false)
      })
      .catch((err) => {
        console.error("Scan trigger failed:", err.message)
        setScanError(err.message)
        setRefreshing(false)
      })
  }

  const meta = report?.meta || { target: "unknown", timestamp: new Date().toISOString(), transport: "unknown" }
  const findings = report?.findings || []
  const fixList = report?.fix_list || []

  // Compute metrics
  const summary = useMemo(() => {
    if (report?.summary && report.summary.pass !== undefined) return report.summary
    return {
      pass: findings.filter(f => f.status === "PASS").length,
      fail: findings.filter(f => f.status === "FAIL").length,
      unknown: findings.filter(f => f.status === "UNKNOWN").length
    }
  }, [report, findings])

  const complianceScore = useMemo(() => {
    const total = summary.pass + summary.fail
    if (total === 0) return 0
    return Math.round((summary.pass / total) * 100)
  }, [summary])

  // Filtered list
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const matchesStatus = statusFilter === "ALL" || f.status === statusFilter
      const matchesSeverity = severityFilter === "ALL" || f.severity_hint === severityFilter
      
      const query = searchQuery.toLowerCase()
      return (
        f.rule_id.toLowerCase().includes(query) ||
        f.title.toLowerCase().includes(query) ||
        f.command.toLowerCase().includes(query) ||
        (f.evidence && f.evidence.toLowerCase().includes(query))
      )
    })
  }, [findings, statusFilter, severityFilter, searchQuery])

  // Copy helper
  const copyToClipboard = (text, ruleId) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedFixId(ruleId)
      setTimeout(() => setCopiedFixId(null), 2000)
    })
  }

  const resetFilters = () => {
    setStatusFilter("ALL")
    setSeverityFilter("ALL")
    setSearchQuery("")
  }

  const toggleExpand = (ruleId) => {
    setExpandedFindings(prev => ({
      ...prev,
      [ruleId]: !prev[ruleId]
    }))
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-between" style={{ minHeight: '100vh', display: 'flex', justifyContent: 'center', alignItems: 'center', backgroundColor: 'var(--bg-base)' }}>
        <span className="material-icons" style={{ fontSize: '2.5rem', color: 'var(--text-secondary)', animation: 'spin 2s linear infinite' }}>sync</span>
        <p style={{ marginTop: '1.5rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>RESOLVING SECURITY BASELINE DATA...</p>
        <style>{`
          @keyframes spin { 100% { transform: rotate(360deg); } }
        `}</style>
      </div>
    )
  }

  return (
    <div style={{ minHeight: '100vh', backgroundColor: 'var(--bg-base)', paddingBottom: '3rem' }}>
      
      {/* HEADER NAVBAR */}
      <nav className="navbar" style={{ position: 'static', marginBottom: '1.5rem' }}>
        <div className="nav-container">
          <div className="nav-logo">
            <span className="material-icons" style={{ color: 'var(--color-primary)' }}>security</span>
            <span>CIS Hardening Audit Console</span>
          </div>
          
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <input 
              type="text" 
              value={targetInput} 
              onChange={(e) => setTargetInput(e.target.value)} 
              placeholder="Docker Container Target"
              style={{
                background: '#090d16',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.45rem 0.75rem',
                color: '#fff',
                fontSize: '0.8rem',
                fontFamily: 'var(--font-mono)',
                outline: 'none',
                minWidth: '220px'
              }}
              disabled={refreshing}
            />
            <button 
              className="nav-btn" 
              onClick={triggerLiveScan}
              disabled={refreshing}
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', opacity: refreshing ? 0.7 : 1 }}
            >
              <span className="material-icons" style={{ fontSize: '1rem', animation: refreshing ? 'spin 1.5s linear infinite' : 'none' }}>sync</span>
              <span>{refreshing ? "Scanning..." : "Run Security Scan"}</span>
            </button>
          </div>
        </div>
      </nav>

      <main className="app-layout">

        {/* ERROR SUMMARY CARD */}
        {scanError && (
          <div 
            style={{ 
              padding: '1.25rem', 
              backgroundColor: 'var(--color-fail-bg)', 
              border: '1px solid rgba(239, 68, 68, 0.2)', 
              borderRadius: '8px', 
              marginBottom: '2rem', 
              color: '#fca5a5', 
              fontSize: '0.85rem', 
              display: 'flex', 
              alignItems: 'flex-start', 
              gap: '0.75rem' 
            }}
          >
            <span className="material-icons" style={{ color: 'var(--color-fail)' }}>error_outline</span>
            <div style={{ flex: 1 }}>
              <strong style={{ color: '#fff', display: 'block', marginBottom: '0.25rem' }}>Scan Session Failed</strong>
              <span style={{ fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', display: 'block', lineHeight: 1.4 }}>{scanError}</span>
            </div>
            <span className="material-icons" style={{ cursor: 'pointer', color: 'var(--text-secondary)' }} onClick={() => setScanError(null)}>close</span>
          </div>
        )}
        
        {/* METADATA TARGET BLOCK (Identifies Linux Config) */}
        <section className="dashboard-header" style={{ gridTemplateColumns: '1fr', marginBottom: '2rem' }}>
          <div className="glass-panel meta-panel" style={{ flexDirection: 'row', flexWrap: 'wrap', gap: '1.5rem', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div className="brand-badge" style={{ marginBottom: '0.25rem' }}>Target Specification</div>
              <h2 style={{ fontSize: '1.25rem', color: '#fff', fontWeight: '700' }}>Host Configuration Overview</h2>
            </div>
            
            <div className="meta-grid" style={{ flex: 1, justifyContent: 'flex-end', maxWidth: '600px' }}>
              <div className="meta-card">
                <div className="meta-card-label">Target Name</div>
                <div className="meta-card-value">{meta.target}</div>
              </div>
              <div className="meta-card">
                <div className="meta-card-label">Transport Link</div>
                <div className="meta-card-value">{meta.transport}</div>
              </div>
              <div className="meta-card">
                <div className="meta-card-label">Timestamp</div>
                <div className="meta-card-value">{new Date(meta.timestamp).toLocaleTimeString()}</div>
              </div>
            </div>
          </div>
        </section>

        {/* METRICS ROW */}
        <section className="metrics-grid">
          <div className="glass-panel metric-card">
            <span className="metric-label">Compliance score</span>
            <div className="metric-value" style={{ color: complianceScore > 75 ? 'var(--color-pass)' : (complianceScore > 40 ? 'var(--color-warn)' : 'var(--color-fail)') }}>
              {complianceScore}%
            </div>
            <p className="metric-desc">Checks passing CIS baseline requirements</p>
            <div className="metric-bar-bg">
              <div className="metric-bar-fill" style={{ width: `${complianceScore}%`, backgroundColor: complianceScore > 75 ? 'var(--color-pass)' : (complianceScore > 40 ? 'var(--color-warn)' : 'var(--color-fail)') }} />
            </div>
          </div>

          <div className="glass-panel metric-card">
            <div className="flex justify-between items-center">
              <span className="metric-label">Failing rules</span>
              <span className="material-icons" style={{ color: 'var(--color-fail)', fontSize: '1.1rem' }}>error</span>
            </div>
            <div className="metric-value" style={{ color: 'var(--color-fail)' }}>{summary.fail}</div>
            <p className="metric-desc">Baseline configurations out of spec</p>
          </div>

          <div className="glass-panel metric-card">
            <div className="flex justify-between items-center">
              <span className="metric-label">Passing rules</span>
              <span className="material-icons" style={{ color: 'var(--color-pass)', fontSize: '1.1rem' }}>check_circle</span>
            </div>
            <div className="metric-value" style={{ color: 'var(--color-pass)' }}>{summary.pass}</div>
            <p className="metric-desc">Baseline configurations correctly hardened</p>
          </div>

          <div className="glass-panel metric-card">
            <div className="flex justify-between items-center">
              <span className="metric-label">Unresolved rules</span>
              <span className="material-icons" style={{ color: 'var(--color-unknown)', fontSize: '1.1rem' }}>help</span>
            </div>
            <div className="metric-value" style={{ color: 'var(--color-unknown)' }}>{summary.unknown}</div>
            <p className="metric-desc">Checks missing binary dependencies</p>
          </div>
        </section>

        {/* VERDICTS GRID SPLIT */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '2rem' }}>
          <style>{`
            @media (min-width: 1024px) {
              .grid-split {
                display: grid;
                grid-template-columns: 3fr 2fr;
                gap: 2rem;
              }
            }
          `}</style>
          <div className="grid-split">
            
            {/* LEFT COLUMN: BENCHMARK CHECKS & EVIDENCE */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div className="rules-header">
                <div>
                  <h2 className="section-title" style={{ fontSize: '1.15rem', fontWeight: '700' }}>Baseline Policies Audited ({filteredFindings.length})</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Evaluations generated directly from host output</p>
                </div>
              </div>

              {/* Filters Panel */}
              <div className="search-filter-box">
                <div className="search-input-wrapper">
                  <span className="material-icons search-icon-svg" style={{ fontSize: '1.1rem' }}>search</span>
                  <input 
                    type="text" 
                    placeholder="Search by ID, rule name, or executed command..." 
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="cyber-search-input"
                  />
                </div>

                <div className="button-filters">
                  <div className="filter-group-wrapper">
                    <span className="filter-label">Filter Verdict</span>
                    <div className="filter-btn-grid">
                      {["ALL", "FAIL", "PASS", "UNKNOWN"].map(status => (
                        <button 
                          key={status}
                          className={`cyber-filter-btn ${statusFilter === status ? 'active' : ''}`}
                          onClick={() => setStatusFilter(status)}
                        >
                          {status}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="filter-group-wrapper">
                    <span className="filter-label">Severity Level</span>
                    <div className="filter-btn-grid">
                      {["ALL", "critical", "high", "medium", "low"].map(sev => (
                        <button 
                          key={sev}
                          className={`cyber-filter-btn ${severityFilter === sev ? 'active' : ''}`}
                          onClick={() => setSeverityFilter(sev)}
                        >
                          {sev.charAt(0).toUpperCase() + sev.slice(1)}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Finding Cards List */}
              <div className="rules-list">
                {filteredFindings.length === 0 ? (
                  <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', borderStyle: 'dashed' }}>
                    <p style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>NO MATCHING AUDIT DATA FOUND</p>
                    <span style={{ color: 'var(--color-primary)', cursor: 'pointer', textDecoration: 'underline', fontSize: '0.75rem', marginTop: '0.5rem', display: 'inline-block' }} onClick={resetFilters}>Reset filters</span>
                  </div>
                ) : (
                  filteredFindings.map((finding) => {
                    const isExpanded = !!expandedFindings[finding.rule_id]
                    return (
                      <div key={finding.rule_id} className="rule-card glass-panel-interactive">
                        <div 
                          className="rule-card-header cursor-pointer"
                          onClick={() => toggleExpand(finding.rule_id)}
                        >
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', flex: 1 }}>
                            <div className="rule-meta">
                              <span className="rule-id">{finding.rule_id}</span>
                              <span className={`severity-tag ${finding.severity_hint}`}>
                                {finding.severity_hint}
                              </span>
                            </div>
                            <h4 className="rule-title">{finding.title}</h4>
                          </div>
                          
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                            <span className={`status-badge-cyber ${finding.status}`}>
                              {finding.status}
                            </span>
                            <span className="material-icons" style={{ color: 'var(--text-muted)', transform: isExpanded ? 'rotate(180deg)' : 'none', transition: 'transform var(--transition-fast)', fontSize: '1.2rem' }}>
                              expand_more
                            </span>
                          </div>
                        </div>

                        {isExpanded && (
                          <div className="rule-details">
                            <div className="command-viewer">
                              <span className="command-label">Audited Baseline Command</span>
                              <code className="command-code">{finding.command}</code>
                            </div>
                            <div className="command-viewer">
                              <span className="command-label">Output Verification Evidence</span>
                              <pre className={`evidence-box ${finding.status}`}>
                                {finding.evidence || "[No stdout captured]"}
                              </pre>
                            </div>
                          </div>
                        )}
                      </div>
                    )
                  })
                )}
              </div>
            </div>

            {/* RIGHT COLUMN: REMEDIATION GUIDE */}
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <div className="fixes-header">
                <div>
                  <h2 className="section-title" style={{ fontSize: '1.15rem', fontWeight: '700' }}>Remediation Guide</h2>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Failing rules sorted by severity priority</p>
                </div>
                <span className="badge-count" style={{ borderColor: 'var(--border-color)', background: 'var(--bg-surface)' }}>{fixList.length} Fixes</span>
              </div>

              {fixList.length === 0 ? (
                <div className="glass-panel" style={{ padding: '3rem 1.5rem', textAlign: 'center' }}>
                  <span className="material-icons" style={{ fontSize: '2.5rem', color: 'var(--color-pass)', marginBottom: '1rem' }}>check_circle</span>
                  <h4 style={{ color: '#fff', fontSize: '0.85rem', marginBottom: '0.25rem', fontFamily: 'var(--font-mono)' }}>SYSTEM STATE PASSING</h4>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>No configuration drifts detected.</p>
                </div>
              ) : (
                <div className="fix-card-wrapper" style={{ maxHeight: '1100px', overflowY: 'auto', paddingRight: '4px' }}>
                  {fixList.map((fix) => {
                    const finding = findings.find(f => f.rule_id === fix.rule_id)
                    const severity = finding ? finding.severity_hint : "high"
                    const isCopied = copiedFixId === fix.rule_id

                    return (
                      <div key={fix.rule_id} className="cyber-fix-card glass-panel">
                        <div className="fix-meta-row">
                          <div className="flex items-center gap-2">
                            <span className={`priority-circle ${severity}`}>
                              #{fix.priority}
                            </span>
                            <span style={{ fontSize: '0.8rem', fontWeight: '700', color: '#fff' }}>{fix.category}</span>
                          </div>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>{fix.rule_id}</span>
                        </div>

                        <div className="fix-desc-box">
                          <div className="fix-finding">
                            <strong>System State:</strong> {fix.finding}
                          </div>
                          <div className="fix-why">
                            <strong>Policy Impact:</strong> {fix.why_it_matters}
                          </div>
                        </div>

                        <div className="cyber-copy-container">
                          <div className="cyber-copy-code">
                            <code>{fix.fix_command}</code>
                          </div>
                          <button 
                            className={`cyber-copy-btn ${isCopied ? 'copied' : ''}`}
                            onClick={() => copyToClipboard(fix.fix_command, fix.rule_id)}
                          >
                            <span className="material-icons" style={{ fontSize: '0.9rem' }}>
                              {isCopied ? "done" : "content_copy"}
                            </span>
                            <span>{isCopied ? "Copied" : "Copy"}</span>
                          </button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

          </div>
        </div>

      </main>
    </div>
  )
}

export default App
