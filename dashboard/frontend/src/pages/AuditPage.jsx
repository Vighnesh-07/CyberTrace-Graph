import { useState, useEffect } from 'react'
import { fetchAuditLog } from '../api'

function AuditPage() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [filterAction, setFilterAction] = useState('')
  const [search, setSearch] = useState('')

  const loadLogs = async () => {
    try {
      setLoading(true)
      const data = await fetchAuditLog(100)
      setLogs(data.entries || [])
    } catch (err) {
      console.error('Failed to load audit log:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadLogs()
    const interval = setInterval(loadLogs, 30000)
    return () => clearInterval(interval)
  }, [])

  const actionColor = (action) => {
    switch (action) {
      case 'BLOCK_IP': return 'var(--danger)'
      case 'ISOLATE_HOST': return 'var(--warning)'
      case 'KILL_PROCESS': return 'var(--accent-primary)'
      default: return 'var(--text-muted)'
    }
  }

  const filteredLogs = logs.filter(log => {
    if (filterAction && log.action !== filterAction) return false;
    if (search) {
      const s = search.toLowerCase()
      return (
        (log.user && log.user.toLowerCase().includes(s)) ||
        (log.target && log.target.toLowerCase().includes(s)) ||
        (log.alert_id && log.alert_id.toLowerCase().includes(s)) ||
        (log.details && log.details.toLowerCase().includes(s))
      )
    }
    return true
  })

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Audit Log</h1>
        <p className="page-subtitle">Track SOAR actions and automated responses</p>
      </div>

      <div className="filter-bar">
        <select value={filterAction} onChange={(e) => setFilterAction(e.target.value)}>
          <option value="">All Actions</option>
          <option value="BLOCK_IP">Block IP</option>
          <option value="ISOLATE_HOST">Isolate Host</option>
          <option value="KILL_PROCESS">Kill Process</option>
        </select>
        <input 
          type="text" 
          placeholder="Search logs..." 
          value={search} 
          onChange={(e) => setSearch(e.target.value)}
          style={{ padding: '8px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-elevated)', color: 'var(--text-primary)' }}
        />
        <button className="btn btn-ghost" onClick={loadLogs}>Refresh</button>
      </div>

      {loading && logs.length === 0 ? (
        <div className="loading-container"><div className="spinner"></div>Loading logs...</div>
      ) : filteredLogs.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">📋</div>
          <p>No audit logs match your filters.</p>
        </div>
      ) : (
        <div className="card">
          <div className="card-body" style={{ padding: 0 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Alert ID</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log, i) => (
                  <tr key={i}>
                    <td className="mono">{new Date(log.timestamp).toLocaleString()}</td>
                    <td>{log.user}</td>
                    <td>
                      <span style={{ 
                        color: actionColor(log.action),
                        fontWeight: 'bold',
                        fontSize: '0.85em',
                        padding: '2px 6px',
                        border: `1px solid ${actionColor(log.action)}`,
                        borderRadius: '4px'
                      }}>
                        {log.action}
                      </span>
                    </td>
                    <td className="mono">{log.target}</td>
                    <td className="mono">{log.alert_id}</td>
                    <td>{log.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default AuditPage
