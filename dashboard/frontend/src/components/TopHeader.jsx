import { useState, useRef, useEffect } from 'react'
import { useAuth } from '../AuthContext'
import { Search, Bell, ChevronDown, LogOut, User, Shield, X } from 'lucide-react'

function TopHeader() {
  const { user, logout } = useAuth()
  const [searchQuery, setSearchQuery] = useState('')
  const [showNotifications, setShowNotifications] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const notifRef = useRef(null)
  const userRef = useRef(null)

  // Close dropdowns on outside click
  useEffect(() => {
    const handler = (e) => {
      if (notifRef.current && !notifRef.current.contains(e.target)) setShowNotifications(false)
      if (userRef.current && !userRef.current.contains(e.target)) setShowUserMenu(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const mockNotifications = [
    { id: 1, severity: 'critical', title: 'Brute Force Attack Detected', detail: '30 failed logins from 10.0.0.15', time: '2m ago', unread: true },
    { id: 2, severity: 'high', title: 'DNS Tunneling Suspected', detail: 'High entropy queries to evil-c2-server.xyz', time: '5m ago', unread: true },
    { id: 3, severity: 'medium', title: 'Lateral Movement Alert', detail: 'Unusual SMB traffic from 192.168.1.50', time: '12m ago', unread: false },
    { id: 4, severity: 'low', title: 'New Device Connected', detail: 'MAC address aa:bb:cc:dd:ee:ff joined network', time: '1h ago', unread: false },
  ]

  const unreadCount = mockNotifications.filter(n => n.unread).length

  const severityDotColor = (sev) => {
    switch (sev) {
      case 'critical': return 'var(--severity-critical)'
      case 'high': return 'var(--severity-high)'
      case 'medium': return 'var(--severity-medium)'
      default: return 'var(--severity-low)'
    }
  }

  return (
    <header className="top-header">
      <div className="top-header-left">
        <div className="header-search">
          <Search size={16} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Search alerts, IPs, domains..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="header-search-input"
          />
          <kbd className="header-search-shortcut">/</kbd>
        </div>
      </div>

      <div className="top-header-right">
        {/* Live status indicator */}
        <div className="header-live-indicator">
          <span className="live-dot"></span>
          <span>Live</span>
        </div>

        {/* Notifications */}
        <div className="header-action-group" ref={notifRef}>
          <button
            className="header-icon-btn"
            onClick={(e) => { e.stopPropagation(); setShowNotifications(prev => !prev); setShowUserMenu(false); }}
            aria-label="Notifications"
          >
            <Bell size={18} />
            {unreadCount > 0 && <span className="header-notification-badge">{unreadCount}</span>}
          </button>

          {showNotifications && (
            <div className="notification-panel">
              <div className="notification-panel-header">
                <span className="notification-panel-title">Notifications</span>
                <button className="notification-panel-close" onClick={() => setShowNotifications(false)}>
                  <X size={14} />
                </button>
              </div>
              <div className="notification-panel-body">
                {mockNotifications.map(n => (
                  <div key={n.id} className={`notification-item ${n.unread ? 'unread' : ''}`}>
                    <span className="notification-dot" style={{ background: severityDotColor(n.severity) }}></span>
                    <div className="notification-content">
                      <div className="notification-title">{n.title}</div>
                      <div className="notification-detail">{n.detail}</div>
                      <div className="notification-time">{n.time}</div>
                    </div>
                    {n.unread && <span className="notification-unread-mark"></span>}
                  </div>
                ))}
              </div>
              <div className="notification-panel-footer">
                <button className="btn btn-ghost" style={{ width: '100%', justifyContent: 'center', fontSize: '0.75rem' }}>View All Notifications</button>
              </div>
            </div>
          )}
        </div>

        {/* User Menu */}
        <div className="header-action-group" ref={userRef}>
          <button
            className="header-user-btn"
            onClick={(e) => { e.stopPropagation(); setShowUserMenu(prev => !prev); setShowNotifications(false); }}
          >
            <div className="header-avatar">
              {user?.username?.charAt(0).toUpperCase() || 'U'}
            </div>
            <div className="header-user-info">
              <span className="header-user-name">{user?.username || 'User'}</span>
              <span className="header-user-role">{user?.role || 'ANALYST'}</span>
            </div>
            <ChevronDown size={14} color="var(--text-muted)" />
          </button>

          {showUserMenu && (
            <div className="header-dropdown">
              <div className="header-dropdown-item">
                <User size={14} />
                <span>Profile</span>
              </div>
              <div className="header-dropdown-item">
                <Shield size={14} />
                <span>Security Settings</span>
              </div>
              <div className="header-dropdown-divider"></div>
              <div className="header-dropdown-item header-dropdown-item--danger" onClick={logout}>
                <LogOut size={14} />
                <span>Sign Out</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}

export default TopHeader
