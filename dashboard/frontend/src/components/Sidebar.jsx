import { NavLink } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { fetchPipelineHealth, fetchAlerts } from '../api'
import { useAuth } from '../AuthContext'
import {
  LayoutDashboard,
  Bell,
  GitGraph,
  Clock,
  Settings,
  Shield,
  Search,
  ChevronDown,
  LogOut,
  User,
  Activity,
  Database,
  Wifi
} from 'lucide-react'

function Sidebar() {
  const [health, setHealth] = useState(null)
  const [alertCount, setAlertCount] = useState(0)
  const { user, logout } = useAuth()

  useEffect(() => {
    const fetchData = async () => {
      try {
        const healthData = await fetchPipelineHealth()
        setHealth(healthData)
      } catch {
        setHealth({ status: 'error', services: { neo4j: 'down', redis: 'down', kafka: 'down' } })
      }
      try {
        const alertsData = await fetchAlerts({ limit: 1 })
        if (alertsData && alertsData.total !== undefined) {
          setAlertCount(alertsData.total)
        }
      } catch (err) {
        console.error("Failed to fetch alert count", err)
      }
    }
    fetchData()
    const interval = setInterval(fetchData, 15000)
    return () => clearInterval(interval)
  }, [])

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <Shield size={20} style={{ marginRight: '8px', color: 'var(--accent-primary)', flexShrink: 0 }} />
          Cyber<span>Trace</span>
        </div>
        <div className="sidebar-subtitle">SOC Dashboard</div>
      </div>
      
      {user && (
        <div style={{ padding: 'var(--space-md) var(--space-lg)', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ 
              width: '32px', height: '32px', 
              borderRadius: '50%', 
              backgroundColor: 'var(--bg-elevated)',
              border: '1px solid var(--border-subtle)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: 'bold', color: 'var(--accent-primary)'
            }}>
              {user.username.charAt(0).toUpperCase()}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '0.875rem', fontWeight: '500', color: 'var(--text-primary)' }}>{user.username}</span>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', backgroundColor: 'var(--bg-elevated)', padding: '2px 6px', borderRadius: '4px', display: 'inline-block', marginTop: '4px', border: '1px solid var(--border-subtle)', width: 'fit-content' }}>{user.role}</span>
            </div>
          </div>
          <button onClick={logout} className="btn btn-ghost" style={{ padding: '6px', color: 'var(--text-muted)' }} title="Logout">
            <LogOut size={16} />
          </button>
        </div>
      )}

      <nav className="sidebar-nav">
        <div className="sidebar-section-label">MONITORING</div>
        <NavLink to="/" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} end>
          <span className="nav-icon"><LayoutDashboard size={18} /></span>
          <span className="nav-label">Dashboard</span>
        </NavLink>
        <NavLink to="/alerts" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <span className="nav-icon"><Bell size={18} /></span>
          <span className="nav-label">Alerts</span>
          {alertCount > 0 && <span className="nav-badge">{alertCount}</span>}
        </NavLink>

        <div className="sidebar-section-label">ANALYSIS</div>
        <NavLink to="/graph" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <span className="nav-icon"><GitGraph size={18} /></span>
          <span className="nav-label">Graph</span>
        </NavLink>
        <NavLink to="/timeline" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <span className="nav-icon"><Clock size={18} /></span>
          <span className="nav-label">Timeline</span>
        </NavLink>

        <div className="sidebar-section-label">SYSTEM</div>
        <a href="#" className="nav-item" onClick={(e) => e.preventDefault()} style={{ opacity: 0.6, cursor: 'not-allowed' }}>
          <span className="nav-icon"><Settings size={18} /></span>
          <span className="nav-label">Settings</span>
        </a>
      </nav>
      
      <div className="sidebar-footer">
        {health && health.services && Object.entries(health.services).map(([name, status]) => (
          <div key={name} className="health-indicator">
            <span className={`health-dot ${status}`}></span>
            <span className="health-label">{name} &middot; {status === 'up' ? 'Online' : 'Offline'}</span>
          </div>
        ))}
        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textAlign: 'center', marginTop: 'var(--space-md)' }}>
          v1.0.0
        </div>
      </div>
    </aside>
  )
}

export default Sidebar
