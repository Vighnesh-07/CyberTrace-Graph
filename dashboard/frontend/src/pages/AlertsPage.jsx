import { useState, useEffect } from 'react'
import { fetchAlerts, updateAlertStatus } from '../api'
import { useAuth } from '../AuthContext'

function AlertsPage() {
  const { user } = useAuth()
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterStatus, setFilterStatus] = useState('')

  const loadAlerts = async () => {
    try {
      setLoading(true)
      const params = { limit: 100 }
      if (filterSeverity) params.severity = filterSeverity
      if (filterStatus) params.status = filterStatus
      const data = await fetchAlerts(params)
      setAlerts(data.alerts || [])
    } catch (err) {
      console.error('Failed to load alerts:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadAlerts() }, [filterSeverity, filterStatus])

  const handleStatusUpdate = async (alertId, newStatus) => {
    try {
      await updateAlertStatus(alertId, newStatus)
      loadAlerts()
    } catch (err) {
      console.error('Failed to update status:', err)
    }
  }

  const severityClass = (sev) => {
    const s = (sev || '').toLowerCase()
    if (s === 'critical' || s === 'high') return 'critical'
    if (s === 'medium') return 'medium'
    return 'low'
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Alerts</h1>
        <p className="page-subtitle">Security alerts with SOAR response actions</p>
      </div>

      <div className="filter-bar">
        <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="CLOSED">Closed</option>
        </select>
        <button className="btn btn-ghost" onClick={loadAlerts}>Refresh</button>
      </div>

      {loading ? (
        <div className="loading-container"><div className="spinner"></div>Loading alerts...</div>
      ) : alerts.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">✓</div>
          <p>No alerts match your filters.</p>
        </div>
      ) : (
        <div className="card">
          <div className="card-body" style={{ padding: 0 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Source IP</th>
                  <th>Title</th>
                  <th>Confidence</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert, i) => (
                  <tr key={alert.alert_id || i}>
                    <td><span className={`badge badge-${severityClass(alert.severity)}`}>{alert.severity || 'N/A'}</span></td>
                    <td className="mono">{alert.alert_type || 'N/A'}</td>
                    <td className="mono">{alert.source_ip || '—'}</td>
                    <td>{alert.title || 'Alert'}</td>
                    <td className="mono">{alert.confidence_score ? `${(alert.confidence_score * 100).toFixed(0)}%` : '—'}</td>
                    <td><span className={`badge badge-${(alert.status || 'open').toLowerCase()}`}>{alert.status || 'OPEN'}</span></td>
                    <td>
                      <div style={{ display: 'flex', gap: '4px' }}>
                        {alert.status !== 'ACKNOWLEDGED' && (
                          <button className="btn btn-ghost" onClick={() => handleStatusUpdate(alert.alert_id, 'ACKNOWLEDGED')}>Ack</button>
                        )}
                        {alert.status !== 'INVESTIGATING' && (
                          <button className="btn btn-primary" onClick={() => handleStatusUpdate(alert.alert_id, 'INVESTIGATING')}>Investigate</button>
                        )}
                        {alert.status !== 'CLOSED' && user?.role === 'ADMIN' && (
                          <button className="btn btn-danger" onClick={() => handleStatusUpdate(alert.alert_id, 'CLOSED')}>Close</button>
                        )}
                      </div>
                    </td>
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

export default AlertsPage
