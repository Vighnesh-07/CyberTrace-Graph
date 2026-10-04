import React, { useState, useEffect } from 'react'
import { fetchAlerts, updateAlertStatus, blockIP, isolateHost, killProcess, fetchSOARActions } from '../api'
import { useAuth } from '../AuthContext'

function AlertDetails({ alert, onActionComplete }) {
  const [actions, setActions] = useState([])
  const [loadingActions, setLoadingActions] = useState(true)
  const [reason, setReason] = useState('')
  const [processName, setProcessName] = useState('')
  const [isExecuting, setIsExecuting] = useState(false)
  const [toast, setToast] = useState(null)
  
  const loadActions = async () => {
    try {
      setLoadingActions(true)
      const data = await fetchSOARActions(alert.alert_id)
      setActions(data.actions || [])
    } catch (err) {
      console.error('Failed to load actions:', err)
    } finally {
      setLoadingActions(false)
    }
  }

  useEffect(() => {
    loadActions()
  }, [alert.alert_id])

  const showToast = (message, type = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3000)
  }

  const handleSOARAction = async (actionType) => {
    if (!reason) {
      showToast('Please provide a reason', 'error')
      return
    }
    
    if (actionType === 'KILL_PROCESS' && !processName) {
      showToast('Please provide a process name', 'error')
      return
    }

    setIsExecuting(true)
    try {
      if (actionType === 'BLOCK_IP') {
        await blockIP(alert.source_ip, alert.alert_id, reason)
      } else if (actionType === 'ISOLATE_HOST') {
        // Assume hostname is available or fallback to source_ip
        const targetHost = alert.hostname || alert.source_ip || 'unknown'
        await isolateHost(targetHost, alert.alert_id, reason)
      } else if (actionType === 'KILL_PROCESS') {
        const targetHost = alert.hostname || alert.source_ip || 'unknown'
        await killProcess(targetHost, processName, alert.alert_id, reason)
      }
      
      showToast(`${actionType} action executed successfully`)
      setReason('')
      setProcessName('')
      await loadActions()
      if (onActionComplete) onActionComplete()
    } catch (err) {
      showToast(`Action failed: ${err.message}`, 'error')
    } finally {
      setIsExecuting(false)
    }
  }

  return (
    <div style={{ padding: '20px', backgroundColor: 'var(--bg-elevated)', borderBottom: '1px solid var(--border-subtle)' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div>
          <h3 style={{ marginTop: 0, marginBottom: '10px' }}>Alert Details</h3>
          <p><strong>Title:</strong> {alert.title || 'N/A'}</p>
          <p><strong>Description:</strong> {alert.description || 'N/A'}</p>
          <p><strong>Source IP:</strong> {alert.source_ip || 'N/A'}</p>
          <p><strong>MITRE Tactic:</strong> {alert.mitre_tactic || 'N/A'}</p>
          <p><strong>MITRE Technique:</strong> {alert.mitre_technique || 'N/A'}</p>
          <p><strong>Confidence:</strong> {alert.confidence_score ? `${(alert.confidence_score * 100).toFixed(0)}%` : 'N/A'}</p>
        </div>
        
        <div>
          <h3 style={{ marginTop: 0, marginBottom: '10px' }}>SOAR Response Actions</h3>
          
          <div style={{ marginBottom: '15px' }}>
            <input 
              type="text" 
              placeholder="Reason for action (required)" 
              value={reason} 
              onChange={e => setReason(e.target.value)}
              style={{ width: '100%', padding: '8px', marginBottom: '10px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-base)', color: 'var(--text-primary)' }}
            />
            
            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <button 
                className="btn btn-primary" 
                onClick={() => handleSOARAction('BLOCK_IP')}
                disabled={isExecuting || !alert.source_ip}
              >
                🛡️ Block IP
              </button>
              <button 
                className="btn btn-warning" 
                onClick={() => handleSOARAction('ISOLATE_HOST')}
                disabled={isExecuting}
                style={{ backgroundColor: 'var(--warning)', color: '#000', border: 'none', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', fontWeight: 500 }}
              >
                🔒 Isolate Host
              </button>
            </div>
            
            <div style={{ display: 'flex', gap: '10px', marginTop: '10px', alignItems: 'center' }}>
              <input 
                type="text" 
                placeholder="Process Name" 
                value={processName} 
                onChange={e => setProcessName(e.target.value)}
                style={{ flex: 1, padding: '8px', borderRadius: '4px', border: '1px solid var(--border-subtle)', background: 'var(--bg-base)', color: 'var(--text-primary)' }}
              />
              <button 
                className="btn btn-danger" 
                onClick={() => handleSOARAction('KILL_PROCESS')}
                disabled={isExecuting}
              >
                ⚡ Kill Process
              </button>
            </div>
          </div>
          
          {isExecuting && <div style={{ color: 'var(--accent-primary)', marginBottom: '10px' }}><div className="spinner" style={{ display: 'inline-block', width: '16px', height: '16px', marginRight: '8px' }}></div>Executing action...</div>}
          
          {toast && (
            <div style={{ 
              padding: '10px', 
              borderRadius: '4px', 
              marginBottom: '10px',
              backgroundColor: toast.type === 'error' ? 'var(--danger)' : 'var(--success)',
              color: '#fff'
            }}>
              {toast.message}
            </div>
          )}
        </div>
      </div>
      
      <div style={{ marginTop: '20px' }}>
        <h3 style={{ marginBottom: '10px' }}>Action History</h3>
        {loadingActions ? (
          <p>Loading history...</p>
        ) : actions.length === 0 ? (
          <p style={{ color: 'var(--text-muted)' }}>No previous SOAR actions for this alert.</p>
        ) : (
          <table className="data-table" style={{ width: '100%', fontSize: '0.9em' }}>
            <thead>
              <tr>
                <th>Time</th>
                <th>Action</th>
                <th>Target</th>
                <th>User</th>
                <th>Status</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {actions.map((act, i) => (
                <tr key={act.action_id || i}>
                  <td className="mono">{act.executed_at ? new Date(act.executed_at).toLocaleString() : 'N/A'}</td>
                  <td><strong>{act.action_type}</strong></td>
                  <td className="mono">{act.target}</td>
                  <td>{act.executed_by}</td>
                  <td><span className="badge" style={{ backgroundColor: act.status === 'COMPLETED' ? 'var(--success)' : 'var(--text-muted)' }}>{act.status}</span></td>
                  <td>{act.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function AlertsPage() {
  const { user } = useAuth()
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [expandedAlertId, setExpandedAlertId] = useState(null)

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

  const handleStatusUpdate = async (alertId, newStatus, e) => {
    if (e) e.stopPropagation();
    try {
      await updateAlertStatus(alertId, newStatus)
      loadAlerts()
    } catch (err) {
      console.error('Failed to update status:', err)
    }
  }

  const toggleExpand = (alertId) => {
    if (expandedAlertId === alertId) {
      setExpandedAlertId(null)
    } else {
      setExpandedAlertId(alertId)
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
                  <React.Fragment key={alert.alert_id || i}>
                    <tr onClick={() => toggleExpand(alert.alert_id)} style={{ cursor: 'pointer' }}>
                      <td><span className={`badge badge-${severityClass(alert.severity)}`}>{alert.severity || 'N/A'}</span></td>
                      <td className="mono">{alert.alert_type || 'N/A'}</td>
                      <td className="mono">{alert.source_ip || '—'}</td>
                      <td>{alert.title || 'Alert'}</td>
                      <td className="mono">{alert.confidence_score ? `${(alert.confidence_score * 100).toFixed(0)}%` : '—'}</td>
                      <td><span className={`badge badge-${(alert.status || 'open').toLowerCase()}`}>{alert.status || 'OPEN'}</span></td>
                      <td>
                        <div style={{ display: 'flex', gap: '4px' }}>
                          {alert.status !== 'ACKNOWLEDGED' && (
                            <button className="btn btn-ghost" onClick={(e) => handleStatusUpdate(alert.alert_id, 'ACKNOWLEDGED', e)}>Ack</button>
                          )}
                          {alert.status !== 'INVESTIGATING' && (
                            <button className="btn btn-primary" onClick={(e) => handleStatusUpdate(alert.alert_id, 'INVESTIGATING', e)}>Investigate</button>
                          )}
                          {alert.status !== 'CLOSED' && user?.role === 'ADMIN' && (
                            <button className="btn btn-danger" onClick={(e) => handleStatusUpdate(alert.alert_id, 'CLOSED', e)}>Close</button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {expandedAlertId === alert.alert_id && (
                      <tr>
                        <td colSpan="7" style={{ padding: 0 }}>
                          <AlertDetails alert={alert} onActionComplete={loadAlerts} />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
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
