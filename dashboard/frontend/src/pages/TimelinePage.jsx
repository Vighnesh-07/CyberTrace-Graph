import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { fetchTimeline } from '../api'

function TimelinePage() {
  const { ip } = useParams()
  const [searchIp, setSearchIp] = useState(ip || '')
  const [timeline, setTimeline] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const loadTimeline = async (targetIp) => {
    if (!targetIp) return
    try {
      setLoading(true)
      setError(null)
      const data = await fetchTimeline(targetIp)
      setTimeline(data)
    } catch (err) {
      setError(`Failed to load timeline for ${targetIp}`)
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (ip) loadTimeline(ip)
  }, [ip])

  const handleSearch = (e) => {
    e.preventDefault()
    loadTimeline(searchIp)
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Attack Timeline</h1>
        <p className="page-subtitle">Chronological activity for a specific IP address</p>
      </div>

      <form onSubmit={handleSearch} className="filter-bar">
        <input
          type="text"
          value={searchIp}
          onChange={(e) => setSearchIp(e.target.value)}
          placeholder="Enter IP address (e.g., 192.168.1.50)"
          style={{ minWidth: '280px' }}
        />
        <button type="submit" className="btn btn-primary">Search</button>
      </form>

      {loading && (
        <div className="loading-container"><div className="spinner"></div>Loading timeline...</div>
      )}

      {error && (
        <div className="empty-state"><p style={{ color: 'var(--severity-critical)' }}>{error}</p></div>
      )}

      {timeline && !loading && (
        <div className="card">
          <div className="card-header">
            <span className="card-title" style={{ fontFamily: 'var(--font-mono)' }}>{timeline.ip}</span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{timeline.total} events</span>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            {timeline.events.length === 0 ? (
              <div className="empty-state">
                <p>No activity found for this IP.</p>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Target Type</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {timeline.events.map((event, i) => (
                    <tr key={i}>
                      <td className="mono">{event.timestamp || '—'}</td>
                      <td><span className="badge badge-medium">{event.action}</span></td>
                      <td>{event.target_type || '—'}</td>
                      <td className="mono" style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {event.target_props ? (event.target_props.name || event.target_props.address || event.target_props.domain || JSON.stringify(event.target_props).slice(0, 60)) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {!timeline && !loading && !error && (
        <div className="empty-state">
          <div className="empty-state-icon">⧖</div>
          <p>Enter an IP address above to view its attack timeline.</p>
        </div>
      )}
    </div>
  )
}

export default TimelinePage
