import { NavLink } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { fetchPipelineHealth } from '../api'
import { useAuth } from '../AuthContext'

function Sidebar() {
  const [health, setHealth] = useState(null)
  const { user, logout } = useAuth()

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const data = await fetchPipelineHealth()
        setHealth(data)
      } catch {
        setHealth({ status: 'error', services: { neo4j: 'down', redis: 'down', kafka: 'down' } })
      }
    }
    checkHealth()
    const interval = setInterval(checkHealth, 15000)
    return () => clearInterval(interval)
  }, [])

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">Cyber<span>Trace</span></div>
        <div className="sidebar-subtitle">SOC Dashboard</div>
      </div>
      
      {user && (
        <div style={{ padding: 'var(--space-md) var(--space-lg)', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: '0.875rem', fontWeight: '500', color: 'var(--text-primary)' }}>{user.username}</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{user.role}</div>
          </div>
          <button onClick={logout} className="btn btn-ghost" style={{ padding: '4px 8px', fontSize: '0.75rem' }}>Logout</button>
        </div>
      )}

      <nav className="sidebar-nav">
        <NavLink to="/" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} end>
          <span className="nav-icon">▦</span>
          <span className="nav-label">Dashboard</span>
        </NavLink>
        <NavLink to="/alerts" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <span className="nav-icon">⚠</span>
          <span className="nav-label">Alerts</span>
        </NavLink>
        <NavLink to="/graph" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <span className="nav-icon">◎</span>
          <span className="nav-label">Graph</span>
        </NavLink>
        <NavLink to="/timeline" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <span className="nav-icon">⧖</span>
          <span className="nav-label">Timeline</span>
        </NavLink>
      </nav>
      <div className="sidebar-footer">
        {health && health.services && Object.entries(health.services).map(([name, status]) => (
          <div key={name} className="health-indicator">
            <span className={`health-dot ${status}`}></span>
            <span className="health-label">{name}</span>
          </div>
        ))}
      </div>
    </aside>
  )
}

export default Sidebar
