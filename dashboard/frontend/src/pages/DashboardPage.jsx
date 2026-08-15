import { useState, useEffect } from 'react'
import { fetchAlerts, fetchGraphStats, fetchPipelineStats, fetchAnalyticsSeverity, fetchAnalyticsTimeline, fetchAnalyticsTechniques } from '../api'
import { useNavigate } from 'react-router-dom'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts'
import { Activity, ShieldAlert, Cpu, Network, Database, Shield } from 'lucide-react'

function DashboardPage() {
  const [alerts, setAlerts] = useState([])
  const [graphStats, setGraphStats] = useState(null)
  const [pipelineStats, setPipelineStats] = useState(null)
  const [severityData, setSeverityData] = useState([])
  const [timelineData, setTimelineData] = useState([])
  const [techniqueData, setTechniqueData] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const [alertCount, setAlertCount] = useState(0)

  useEffect(() => {
    const loadData = async () => {
      try {
        const [alertData, gStats, pStats, sevData, timeData, techData] = await Promise.all([
          fetchAlerts({ limit: 10 }),
          fetchGraphStats(),
          fetchPipelineStats(),
          fetchAnalyticsSeverity(),
          fetchAnalyticsTimeline(),
          fetchAnalyticsTechniques()
        ])
        setAlerts(alertData.alerts || [])
        setAlertCount(alertData.total || 0)
        setGraphStats(gStats)
        setPipelineStats(pStats)
        
        // Format chart data
        const COLORS = {
          CRITICAL: '#ef4444',
          HIGH: '#f97316',
          MEDIUM: '#eab308',
          LOW: '#22c55e'
        }
        setSeverityData(sevData.map(d => ({ ...d, name: d.severity, value: d.count, color: COLORS[d.severity] || COLORS.LOW })))
        setTimelineData(timeData.map(d => ({ name: d.time.split(' ')[1], value: d.count })).reverse())
        setTechniqueData(techData.map(d => ({ name: d.technique, count: d.count })))

      } catch (err) {
        console.error('Dashboard load error:', err)
      } finally {
        setLoading(false)
      }
    }
    loadData()
    const interval = setInterval(loadData, 10000)
    return () => clearInterval(interval)
  }, [])

  const severityClass = (sev) => {
    const s = (sev || '').toLowerCase()
    if (s === 'critical' || s === 'high') return 'critical'
    if (s === 'medium') return 'medium'
    return 'low'
  }

  const totalNodes = graphStats?.nodes ? Object.values(graphStats.nodes).reduce((a, b) => a + b, 0) : 0
  const totalRels = graphStats?.relationships ? Object.values(graphStats.relationships).reduce((a, b) => a + b, 0) : 0

  if (loading) {
    return <div className="loading-container"><div className="spinner"></div>Loading dashboard...</div>
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">SOC Dashboard</h1>
        <p className="page-subtitle">Real-time threat landscape and analytics</p>
      </div>

      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 'var(--space-2xl)' }}>
        <div className="stat-card" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
          <div style={{ padding: 'var(--space-md)', background: 'rgba(239, 68, 68, 0.1)', borderRadius: 'var(--radius-lg)' }}>
            <ShieldAlert color="var(--severity-critical)" size={32} />
          </div>
          <div>
            <div className="stat-label">ACTIVE ALERTS</div>
            <div className={`stat-value ${alertCount > 0 ? 'critical' : 'low'}`}>{alertCount}</div>
          </div>
        </div>
        <div className="stat-card" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
          <div style={{ padding: 'var(--space-md)', background: 'rgba(59, 130, 246, 0.1)', borderRadius: 'var(--radius-lg)' }}>
            <Activity color="var(--accent-primary)" size={32} />
          </div>
          <div>
            <div className="stat-label">Events Processed</div>
            <div className="stat-value">{pipelineStats?.events_processed || 0}</div>
          </div>
        </div>
        <div className="stat-card" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
           <div style={{ padding: 'var(--space-md)', background: 'rgba(168, 85, 247, 0.1)', borderRadius: 'var(--radius-lg)' }}>
            <Network color="#a855f7" size={32} />
          </div>
          <div>
            <div className="stat-label">Graph Nodes</div>
            <div className="stat-value">{totalNodes}</div>
          </div>
        </div>
        <div className="stat-card" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
           <div style={{ padding: 'var(--space-md)', background: 'rgba(234, 179, 8, 0.1)', borderRadius: 'var(--radius-lg)' }}>
            <Cpu color="var(--severity-medium)" size={32} />
          </div>
          <div>
            <div className="stat-label">ML Detections</div>
            <div className="stat-value medium">{pipelineStats?.ml_dga_detections + pipelineStats?.ml_anomaly_detections || 0}</div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: 'var(--space-lg)', marginBottom: 'var(--space-lg)' }}>
        
        {/* Main Timeline Chart */}
        <div className="card" style={{ gridColumn: 'span 2' }}>
          <div className="card-header">
            <span className="card-title">Alert Volume (24h)</span>
          </div>
          <div className="card-body" style={{ height: '300px' }}>
            {timelineData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--severity-critical)" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="var(--severity-critical)" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                    <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                    <YAxis stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                    <RechartsTooltip 
                      contentStyle={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)' }}
                      itemStyle={{ color: 'var(--text-primary)' }}
                    />
                    <Area type="monotone" dataKey="value" stroke="var(--severity-critical)" fillOpacity={1} fill="url(#colorValue)" />
                  </AreaChart>
                </ResponsiveContainer>
            ) : (
                <div className="empty-state" style={{ padding: 'var(--space-lg)' }}>No data</div>
            )}
          </div>
        </div>

        {/* Severity Donut */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Severity Breakdown</span>
          </div>
          <div className="card-body" style={{ height: '300px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
             {severityData.length > 0 ? (
               <ResponsiveContainer width="100%" height="100%">
                 <PieChart>
                   <Pie
                     data={severityData}
                     cx="50%"
                     cy="50%"
                     innerRadius={60}
                     outerRadius={90}
                     paddingAngle={5}
                     dataKey="value"
                     stroke="none"
                   >
                     {severityData.map((entry, index) => (
                       <Cell key={`cell-${index}`} fill={entry.color} />
                     ))}
                   </Pie>
                   <RechartsTooltip 
                      contentStyle={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)' }}
                   />
                 </PieChart>
               </ResponsiveContainer>
             ) : (
                <div className="empty-state" style={{ padding: 'var(--space-lg)' }}>No data</div>
             )}
          </div>
        </div>

      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 'var(--space-lg)', marginBottom: 'var(--space-xl)' }}>
        
        {/* Top MITRE Techniques */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Top MITRE Techniques</span>
          </div>
          <div className="card-body" style={{ height: '350px' }}>
            {techniqueData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={techniqueData} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={true} vertical={false} />
                    <XAxis type="number" stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                    <YAxis dataKey="name" type="category" stroke="var(--text-primary)" fontSize={12} tickLine={false} axisLine={false} width={80} />
                    <RechartsTooltip 
                      contentStyle={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)' }}
                      cursor={{fill: 'var(--bg-hover)'}}
                    />
                    <Bar dataKey="count" fill="var(--severity-high)" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
            ) : (
                <div className="empty-state" style={{ padding: 'var(--space-lg)' }}>No data</div>
            )}
          </div>
        </div>

        {/* Alerts Table */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Recent Alerts</span>
            <button className="btn btn-ghost" onClick={() => navigate('/alerts')}>View All</button>
          </div>
          <div className="card-body" style={{ padding: 0, height: '350px', overflowY: 'auto' }}>
            {alerts.length === 0 ? (
              <div className="empty-state" style={{ padding: 'var(--space-lg)' }}>
                <div className="empty-state-icon">✓</div>
                <p>No active alerts. System is clean.</p>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Source IP</th>
                    <th>Title</th>
                    <th>Confidence</th>
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
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default DashboardPage
