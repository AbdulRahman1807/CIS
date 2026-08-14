import { useState, useEffect, useMemo } from 'react'

// Mock fallback data in case the scanner hasn't generated report.json yet
const mockReport = {
  meta: {
    target: "cis-misconfigured-demo",
    timestamp: new Date().toISOString(),
    transport: "docker"
  },
  summary: {
    pass: 3,
    fail: 6,
    unknown: 1
  },
  findings: [
    {
      rule_id: "CIS-5.2.10",
      title: "SSH root login disabled",
      command: "grep -iE '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config",
      status: "FAIL",
      evidence: "PermitRootLogin yes",
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
      evidence: "PASS_MIN_LEN 5",
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
      evidence: "root:shadow 640",
      severity_hint: "high"
    },
    {
      rule_id: "CIS-6.1.10",
      title: "No world-writable files in /etc, /usr/bin, /usr/sbin",
      command: "find /etc /usr/bin /usr/sbin -xdev -type f -perm -0002",
      status: "FAIL",
      evidence: "/etc/writable_file_planted\n/usr/bin/some_writable_file",
      severity_hint: "medium"
    },
    {
      rule_id: "CIS-3.5.1",
      title: "Firewall active",
      command: "iptables -L INPUT -n",
      status: "UNKNOWN",
      evidence: "iptables: executable file not found",
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
      evidence: "No accounts with empty passwords found",
      severity_hint: "critical"
    },
    {
      rule_id: "CIS-5.2.9",
      title: "No blanket NOPASSWD:ALL in sudoers",
      command: "grep -r NOPASSWD /etc/sudoers /etc/sudoers.d",
      status: "FAIL",
      evidence: "/etc/sudoers:ALL ALL=(ALL) NOPASSWD:ALL",
      severity_hint: "high"
    }
  ],
  fix_list: [
    {
      priority: 1,
      rule_id: "CIS-5.2.10",
      category: "SSH hardening",
      finding: "Root login over SSH is permitted (permitrootlogin yes).",
      why_it_matters: "A leaked or brute-forced root credential grants full remote access with no separate privilege step.",
      fix_command: "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
      evidence_ref: "CIS-5.2.10"
    },
    {
      priority: 2,
      rule_id: "CIS-5.2.11",
      category: "SSH hardening",
      finding: "Password authentication is enabled (passwordauthentication yes).",
      why_it_matters: "Password login exposes the SSH service to automated dictionary and brute-force attacks.",
      fix_command: "sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
      evidence_ref: "CIS-5.2.11"
    },
    {
      priority: 3,
      rule_id: "CIS-5.2.9",
      category: "Sudo configuration",
      finding: "Blanket NOPASSWD wildcard found in sudoers.",
      why_it_matters: "Allows execution of administrative commands as root without authentication, permitting easy privilege escalation.",
      fix_command: "sudo sed -i '/NOPASSWD/d' /etc/sudoers",
      evidence_ref: "CIS-5.2.9"
    },
    {
      priority: 4,
      rule_id: "CIS-5.3.1",
      category: "Password policy",
      finding: "Minimum password length is 5 (minimum is 14).",
      why_it_matters: "Short passwords can be cracked in seconds using modern offline attack techniques.",
      fix_command: "sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 14/' /etc/login.defs",
      evidence_ref: "CIS-5.3.1"
    },
    {
      priority: 5,
      rule_id: "CIS-2.2.4",
      category: "Updates",
      finding: "Automatic security upgrades are not configured.",
      why_it_matters: "Unpatched vulnerabilities are the primary entry point for automated exploits.",
      fix_command: "echo 'APT::Periodic::Update-Package-Lists \"1\";\\nAPT::Periodic::Unattended-Upgrade \"1\";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades",
      evidence_ref: "CIS-2.2.4"
    },
    {
      priority: 6,
      rule_id: "CIS-6.1.10",
      category: "Permissions",
      finding: "Planted world-writable file found under /etc.",
      why_it_matters: "Allows any unprivileged user to overwrite critical configuration files and compromise the system.",
      fix_command: "sudo chmod o-w /etc/writable_file_planted /usr/bin/some_writable_file",
      evidence_ref: "CIS-6.1.10"
    }
  ],
  unknowns: [
    {
      rule_id: "CIS-3.5.1",
      title: "Firewall active",
      command: "iptables -L INPUT -n",
      status: "UNKNOWN",
      evidence: "iptables: executable file not found",
      severity_hint: "high"
    }
  ]
}

function App() {
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  // Fetch report data
  useEffect(() => {
    // Try to load /report.json first, fallback to /api/report if that fails,
    // and finally load mock data if both are unavailable (e.g. running statically).
    fetch('/report.json')
      .then((res) => {
        if (!res.ok) return fetch('/api/report')
        return res
      })
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load report from server endpoints')
        return res.json()
      })
      .then((data) => {
        if (!data || Object.keys(data).length === 0 || data.error) {
          throw new Error(data?.error || 'Empty report returned')
        }
        setReport(data)
        setLoading(false)
      })
      .catch((err) => {
        console.warn('Backend server report loading failed. Falling back to mock data. Reason:', err.message)
        // Check if report data is defined on window (e.g. injected by Python http server)
        if (window.AUDIT_REPORT) {
          setReport(window.AUDIT_REPORT)
        } else {
          setReport(mockReport)
        }
        setLoading(false)
      })
  }, [])

  const [statusFilter, setStatusFilter] = useState("ALL")
  const [severityFilter, setSeverityFilter] = useState("ALL")
  const [searchQuery, setSearchQuery] = useState("")
  const [expandedFindings, setExpandedFindings] = useState({})
  const [copiedFixId, setCopiedFixId] = useState(null)

  // Memoize parameters and filters
  const meta = report?.meta || { target: "unknown", timestamp: new Date().toISOString(), transport: "unknown" }
  const findings = report?.findings || []
  const fixList = report?.fix_list || []

  const summary = useMemo(() => {
    if (report?.summary && report.summary.pass !== undefined) return report.summary
    return {
      pass: findings.filter(f => f.status === "PASS").length,
      fail: findings.filter(f => f.status === "FAIL").length,
      unknown: findings.filter(f => f.status === "UNKNOWN").length
    }
  }, [report, findings])

  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      const matchesStatus = statusFilter === "ALL" || f.status === statusFilter
      const matchesSeverity = severityFilter === "ALL" || f.severity_hint === severityFilter
      
      const query = searchQuery.toLowerCase()
      const matchesSearch = 
        f.rule_id.toLowerCase().includes(query) ||
        f.title.toLowerCase().includes(query) ||
        f.command.toLowerCase().includes(query) ||
        (f.evidence && f.evidence.toLowerCase().includes(query))

      return matchesStatus && matchesSeverity && matchesSearch
    })
  }, [findings, statusFilter, severityFilter, searchQuery])

  const passPercentage = useMemo(() => {
    const total = summary.pass + summary.fail
    if (total === 0) return 0
    return Math.round((summary.pass / total) * 100)
  }, [summary])

  const toggleExpandFinding = (ruleId) => {
    setExpandedFindings(prev => ({
      ...prev,
      [ruleId]: !prev[ruleId]
    }))
  }

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedFixId(id)
      setTimeout(() => setCopiedFixId(null), 2000)
    })
  }

  const resetFilters = () => {
    setStatusFilter("ALL")
    setSeverityFilter("ALL")
    setSearchQuery("")
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-between" style={{ minHeight: '50vh', paddingTop: '20vh' }}>
        <span className="material-icons" style={{ fontSize: '3rem', color: 'var(--text-secondary)', animation: 'spin 2s linear infinite' }}>sync</span>
        <p style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>Loading audit agent report data...</p>
        <style>{`
          @keyframes spin { 100% { transform: rotate(360deg); } }
        `}</style>
      </div>
    )
  }

  return (
    <div className="app-container">
      {/* Header */}
      <header className="header">
        <div>
          <div className="flex items-center gap-2" style={{ marginBottom: '0.5rem' }}>
            <span className="material-icons" style={{ color: 'var(--color-pass)', fontSize: '2rem' }}>security</span>
            <h1 className="header-title">CIS Hardening Audit Results</h1>
          </div>
          <p className="header-subtitle">
            Automated compliance reporting and prioritized fix guidelines
          </p>
        </div>
        <div className="meta-box">
          <div className="meta-row">
            <span className="meta-label">Target Host:</span>
            <span className="meta-val">{meta.target}</span>
          </div>
          <div className="meta-row">
            <span className="meta-label">Transport Protocol:</span>
            <span className="meta-val">{meta.transport}</span>
          </div>
          <div className="meta-row">
            <span className="meta-label">Audited At:</span>
            <span className="meta-val">{new Date(meta.timestamp).toLocaleString()}</span>
          </div>
        </div>
      </header>

      {/* Summary Cards */}
      <section className="summary-grid">
        <div className="summary-card">
          <span className="summary-card-label">Compliance Rating</span>
          <div className="flex items-center" style={{ margin: '0.5rem 0' }}>
            <span className="summary-card-val" style={{ color: passPercentage > 75 ? 'var(--color-pass)' : (passPercentage > 40 ? 'var(--color-medium)' : 'var(--color-critical)') }}>
              {passPercentage}%
            </span>
          </div>
          <div className="progress-bar-bg">
            <div className="progress-bar-fill" style={{ width: `${passPercentage}%`, backgroundColor: passPercentage > 75 ? 'var(--color-pass)' : (passPercentage > 40 ? 'var(--color-medium)' : 'var(--color-critical)') }} />
          </div>
        </div>

        <div className="summary-card">
          <div className="flex justify-between items-center">
            <span className="summary-card-label">Checks Failed</span>
            <span className="material-icons" style={{ color: 'var(--color-fail)', fontSize: '1.25rem' }}>error_outline</span>
          </div>
          <span className="summary-card-val" style={{ color: 'var(--color-fail)' }}>{summary.fail}</span>
          <p className="summary-card-foot">Needs hardening fixes</p>
        </div>

        <div className="summary-card">
          <div className="flex justify-between items-center">
            <span className="summary-card-label">Checks Passed</span>
            <span className="material-icons" style={{ color: 'var(--color-pass)', fontSize: '1.25rem' }}>check_circle_outline</span>
          </div>
          <span className="summary-card-val" style={{ color: 'var(--color-pass)' }}>{summary.pass}</span>
          <p className="summary-card-foot">Configured secure</p>
        </div>

        <div className="summary-card">
          <div className="flex justify-between items-center">
            <span className="summary-card-label">Checks Unknown</span>
            <span className="material-icons" style={{ color: 'var(--color-unknown)', fontSize: '1.25rem' }}>help_outline</span>
          </div>
          <span className="summary-card-val" style={{ color: 'var(--color-unknown)' }}>{summary.unknown}</span>
          <p className="summary-card-foot">Missing binary or permissions</p>
        </div>
      </section>

      {/* Main Grid: Left is Findings list, Right is Priority Fixes */}
      <div className="main-grid">
        <div className="left-column">
          {/* Filters card */}
          <div className="filter-bar">
            <div className="search-container">
              <span className="material-icons search-icon">search</span>
              <input 
                type="text" 
                placeholder="Search rule ID, title, command, or evidence..." 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="search-input"
              />
            </div>
            
            <div className="filter-groups">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', flex: 1 }}>
                <span className="filter-label">Status Filter</span>
                <div className="btn-group">
                  {["ALL", "FAIL", "PASS", "UNKNOWN"].map(status => (
                    <button 
                      key={status}
                      className={`filter-btn ${statusFilter === status ? 'filter-btn-active' : ''}`}
                      onClick={() => setStatusFilter(status)}
                    >
                      {status}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', flex: 1 }}>
                <span className="filter-label">Severity Filter</span>
                <div className="btn-group">
                  {["ALL", "critical", "high", "medium", "low"].map(sev => (
                    <button 
                      key={sev}
                      className={`filter-btn ${severityFilter === sev ? 'filter-btn-active' : ''}`}
                      onClick={() => setSeverityFilter(sev)}
                    >
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Findings List */}
          <div className="flex flex-col gap-4">
            <div className="flex justify-between items-center">
              <h2 className="section-title">Security Rule Audits ({filteredFindings.length})</h2>
              {filteredFindings.length < findings.length && (
                <span className="reset-text" onClick={resetFilters}>Reset Filters</span>
              )}
            </div>

            {filteredFindings.length === 0 ? (
              <div className="empty-state">
                <span className="material-icons" style={{ fontSize: '3rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>search_off</span>
                <p style={{ color: 'var(--text-secondary)' }}>No matching findings found.</p>
              </div>
            ) : (
              filteredFindings.map((finding) => {
                const isExpanded = !!expandedFindings[finding.rule_id]
                return (
                  <div key={finding.rule_id} className="finding-card animate-fade-in">
                    <div 
                      className="finding-header cursor-pointer"
                      onClick={() => toggleExpandFinding(finding.rule_id)}
                    >
                      <div className="flex flex-col gap-2" style={{ flex: 1 }}>
                        <div className="flex items-center gap-2" style={{ flexWrap: 'wrap' }}>
                          <span className="rule-id-badge">{finding.rule_id}</span>
                          <span className={`severity-badge severity-${finding.severity_hint}`}>
                            {finding.severity_hint}
                          </span>
                        </div>
                        <h3 className="finding-title">{finding.title}</h3>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className={`status-badge status-${finding.status}`}>
                          {finding.status}
                        </span>
                        <span className="material-icons" style={{ color: 'var(--text-secondary)', transition: 'transform var(--transition-fast)', transform: isExpanded ? 'rotate(180deg)' : 'none' }}>
                          expand_more
                        </span>
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="finding-details">
                        <div className="detail-row">
                          <span className="detail-label">Command Executed</span>
                          <code className="code-block">{finding.command}</code>
                        </div>
                        <div className="detail-row">
                          <span className="detail-label">
                            {finding.status === "UNKNOWN" ? "Capture Details / Error" : "Capture Evidence"}
                          </span>
                          <pre className={`pre-block status-${finding.status}`}>
                            {finding.evidence || "No command output captured."}
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

        {/* Right column: prioritized remediation fixes */}
        <div className="right-column">
          <div className="sticky-section">
            <div className="flex justify-between items-center" style={{ marginBottom: '1.25rem' }}>
              <div>
                <h2 className="section-title">Remediation Guide</h2>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>Failures ordered by priority</p>
              </div>
              <span className="badge-count">{fixList.length} Fixes</span>
            </div>

            {fixList.length === 0 ? (
              <div className="empty-state">
                <span className="material-icons" style={{ fontSize: '3.5rem', color: 'var(--color-pass)', marginBottom: '1rem' }}>check_circle</span>
                <h3 style={{ color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Host Fully Hardened</h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>No remediation steps required.</p>
              </div>
            ) : (
              <div className="fix-list-container">
                {fixList.map((fix) => {
                  const findingRef = findings.find(f => f.rule_id === fix.rule_id)
                  const severity = findingRef ? findingRef.severity_hint : "high"
                  const isCopied = copiedFixId === fix.rule_id

                  return (
                    <div key={fix.rule_id} className="fix-card">
                      <div className="fix-card-header">
                        <div className="flex items-center gap-2">
                          <span className={`priority-number severity-${severity}`}>
                            #{fix.priority}
                          </span>
                          <span className="fix-category">{fix.category}</span>
                        </div>
                        <span className="fix-rule-id">{fix.rule_id}</span>
                      </div>

                      <div className="fix-body">
                        <p className="fix-finding-text">
                          <strong>Finding:</strong> {fix.finding}
                        </p>
                        <p className="fix-why-text">
                          <strong>Impact:</strong> {fix.why_it_matters}
                        </p>
                      </div>

                      <div className="copy-command-container">
                        <div className="copy-command-code">
                          <code>{fix.fix_command}</code>
                        </div>
                        <button 
                          className={`copy-btn ${isCopied ? 'copied' : ''}`}
                          onClick={() => copyToClipboard(fix.fix_command, fix.rule_id)}
                        >
                          <span className="material-icons" style={{ fontSize: '1rem' }}>
                            {isCopied ? "check" : "content_copy"}
                          </span>
                          <span>{isCopied ? "Copied!" : "Copy"}</span>
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
    </div>
  )
}

export default App
