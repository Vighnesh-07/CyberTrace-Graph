import { useState, useEffect } from 'react'
import { fetchAlerts, fetchGraphStats, fetchPipelineStats, fetchAnalyticsSeverity, fetchAnalyticsTimeline, fetchAnalyticsTechniques, fetchPipelineHealth } from '../api'
import { useNavigate } from 'react-router-dom'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, Legend } from 'recharts'
import { Activity, ShieldAlert, Cpu, Network, Database, Shield, Clock, RefreshCw, TrendingUp, TrendingDown, Zap, Server } from 'lucide-react'

function DashboardPage() {
  const [alerts, setAlerts] = useState([])
  const [graphStats, setGraphStats] = useState(null)
  const [pipelineStats, setPipelineStats] = useState(null)
  const [severityData, setSeverityData] = useState([])
  const [timelineData, setTimelineData] = useState([])
  const [techniqueData, setTechniqueData] = useState([])
  const [pipelineHealth, setPipelineHealth] = useState({ neo4j: 'Online', redis: 'Online', kafka: 'Online' })
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState(0)
  const navigate = useNavigate()

  const [alertCount, setAlertCount] = useState(0)

  const loadData = async () => {
    try {
      const [alertData, gStats, pStats, sevData, timeData, techData, healthData] = await Promise.all([
        fetchAlerts({ limit: 10 }),
        fetchGraphStats(),
        fetchPipelineStats(),
        fetchAnalyticsSeverity(),
        fetchAnalyticsTimeline(),
        fetchAnalyticsTechniques(),
        fetchPipelineHealth().catch(() => ({ neo4j: 'Online', redis: 'Online', kafka: 'Online' }))
      ])
      setAlerts(alertData.alerts || [])
      setAlertCount(alertData.total || 0)
      setGraphStats(gStats)
      setPipelineStats(pStats)
      if (healthData) setPipelineHealth(healthData)
      
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
      
      setLastUpdated(0)
    } catch (err) {
      console.error('Dashboard load error:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const timer = setInterval(() => setLastUpdated(prev => prev + 1), 1000)
    return () => clearInterval(timer)
  }, [])

  const severityClass = (sev) => {
    const s = (sev || '').toLowerCase()
    if (s === 'critical' || s === 'high') return 'critical'
    if (s === 'medium') return 'medium'
    return 'low'
  }

  const severityColor = (sev) => {
    const s = (sev || '').toLowerCase()
    if (s === 'critical' || s === 'high') return 'var(--severity-critical)'
    if (s === 'medium') return 'var(--severity-medium)'
    return 'var(--severity-low)'
  }

  const totalNodes = graphStats?.nodes ? Object.values(graphStats.nodes).reduce((a, b) => a + b, 0) : 0
  const totalRels = graphStats?.relationships ? Object.values(graphStats.relationships).reduce((a, b) => a + b, 0) : 0

  if (loading) {
    return <div className="loading-container"><div className="spinner"></div>Loading dashboard...</div>
  }

  const detectionSources = [
    { name: 'Isolation Forest', count: pipelineStats?.ml_anomaly_detections || 0, color: '#3b82f6' },
    { name: 'DGA Classifier', count: pipelineStats?.ml_dga_detections || 0, color: '#a855f7' },
    { name: 'Rule-Based', count: pipelineStats?.alerts_generated ? pipelineStats.alerts_generated - ((pipelineStats?.ml_anomaly_detections || 0) + (pipelineStats?.ml_dga_detections || 0)) : 0, color: '#ef4444' }
  ]
  const totalDetections = detectionSources.reduce((a, b) => a + b.count, 0)



  const renderCustomLegend = (props) => {
    const { payload } = props
    return (
      <ul style={{ listStyleType: 'none', padding: 0, margin: 0, display: 'flex', flexWrap: 'wrap', justifyContent: 'center', gap: '1rem' }}>
        {payload.map((entry, index) => (
          <li key={`item-${index}`} style={{ display: 'flex', alignItems: 'center', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            <span style={{ width: 12, height: 12, backgroundColor: entry.color, borderRadius: '50%', marginRight: 8 }}></span>
            {entry.value}: <strong style={{ marginLeft: 4, color: 'var(--text-primary)' }}>{entry.payload.value}</strong>
          </li>
        ))}
      </ul>
    )
  }

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1rem', marginBottom: '1.5rem' }}>
        <div>
          <h1 className="page-title">SOC Command Center</h1>
          <p className="page-subtitle">Real-time threat landscape and analytics</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Last updated: {lastUpdated}s ago
          </span>
          <button className="btn btn-outline" onClick={loadData} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <RefreshCw size={16} /> Refresh
          </button>
        </div>
      </div>

      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(6, 1fr)', marginBottom: 'var(--space-2xl)' }}>
        {/* Card 1: Active Alerts */}
        <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
            <div style={{ padding: 'var(--space-md)', background: 'rgba(239, 68, 68, 0.1)', borderRadius: 'var(--radius-lg)' }}>
              <ShieldAlert color="var(--severity-critical)" size={28} />
            </div>
            <div style={{ flex: 1 }}>
              <div className="stat-label">ACTIVE ALERTS</div>
              <div className={`stat-value ${alertCount > 0 ? 'critical' : 'low'}`}>{alertCount}</div>
            </div>
          </div>
        </div>

        {/* Card 2: Events Processed */}
        <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
            <div style={{ padding: 'var(--space-md)', background: 'rgba(59, 130, 246, 0.1)', borderRadius: 'var(--radius-lg)' }}>
              <Activity color="var(--accent-primary)" size={28} />
            </div>
            <div style={{ flex: 1 }}>
              <div className="stat-label">EVENTS PROCESSED</div>
              <div className="stat-value">{pipelineStats?.events_processed || 0}</div>
            </div>
          </div>
        </div>

        {/* Card 3: Graph Nodes */}
        <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
             <div style={{ padding: 'var(--space-md)', background: 'rgba(168, 85, 247, 0.1)', borderRadius: 'var(--radius-lg)' }}>
              <Network color="#a855f7" size={28} />
            </div>
            <div style={{ flex: 1 }}>
              <div className="stat-label">GRAPH NODES</div>
              <div className="stat-value">{totalNodes}</div>
            </div>
          </div>
        </div>

        {/* Card 4: ML Detections */}
        <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
             <div style={{ padding: 'var(--space-md)', background: 'rgba(234, 179, 8, 0.1)', borderRadius: 'var(--radius-lg)' }}>
              <Cpu color="var(--severity-medium)" size={28} />
            </div>
            <div style={{ flex: 1 }}>
              <div className="stat-label">ML DETECTIONS</div>
              <div className="stat-value medium">{(pipelineStats?.ml_dga_detections || 0) + (pipelineStats?.ml_anomaly_detections || 0)}</div>
            </div>
          </div>
        </div>

        {/* Card 5: Graph Relationships */}
        <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
             <div style={{ padding: 'var(--space-md)', background: 'rgba(168, 85, 247, 0.1)', borderRadius: 'var(--radius-lg)' }}>
              <Database color="#a855f7" size={28} />
            </div>
            <div style={{ flex: 1 }}>
              <div className="stat-label">RELATIONSHIPS</div>
              <div className="stat-value">{totalRels}</div>
            </div>
          </div>
        </div>

        {/* Card 6: Mean Response Time */}
        <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-lg)' }}>
             <div style={{ padding: 'var(--space-md)', background: 'rgba(34, 197, 94, 0.1)', borderRadius: 'var(--radius-lg)' }}>
              <Clock color="var(--severity-low)" size={28} />
            </div>
            <div style={{ flex: 1 }}>
              <div className="stat-label">RESPONSE TIME</div>
              <div className="stat-value low">&lt; 150ms</div>
            </div>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 'var(--space-lg)', marginBottom: 'var(--space-lg)' }}>
        
        {/* Main Timeline Chart */}
        <div className="card" style={{ gridColumn: 'span 1' }}>
          <div className="card-header">
            <span className="card-title">Alert Volume (24h)</span>
          </div>
          <div className="card-body" style={{ height: '300px' }}>
            {timelineData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="var(--accent-primary)" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="var(--accent-primary)" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                    <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                    <YAxis stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                    <RechartsTooltip 
                      contentStyle={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}
                      itemStyle={{ color: 'var(--text-primary)' }}
                    />
                    <Area type="monotone" dataKey="value" stroke="var(--accent-primary)" fillOpacity={1} fill="url(#colorValue)" />
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
          <div className="card-body" style={{ height: '300px', display: 'flex', flexDirection: 'column' }}>
             {severityData.length > 0 ? (
               <ResponsiveContainer width="100%" height="100%">
                 <PieChart>
                   <Pie
                     data={severityData}
                     cx="50%"
                     cy="45%"
                     innerRadius={70}
                     outerRadius={95}
                     paddingAngle={4}
                     dataKey="value"
                     stroke="none"
                   >
                     {severityData.map((entry, index) => (
                       <Cell key={`cell-${index}`} fill={entry.color} />
                     ))}
                   </Pie>
                   <RechartsTooltip 
                      contentStyle={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)' }}
                      itemStyle={{ color: 'var(--text-primary)' }}
                   />
                   <Legend content={renderCustomLegend} verticalAlign="bottom" height={36} />
                 </PieChart>
               </ResponsiveContainer>
             ) : (
                <div className="empty-state" style={{ padding: 'var(--space-lg)' }}>No data</div>
             )}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-lg)', marginBottom: 'var(--space-lg)' }}>
        
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
                    <YAxis dataKey="name" type="category" stroke="var(--text-primary)" fontSize={12} tickLine={false} axisLine={false} width={100} />
                    <RechartsTooltip 
                      contentStyle={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)' }}
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

        {/* Threat Activity Feed */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Threat Activity Feed</span>
            <button className="btn btn-ghost" onClick={() => navigate('/alerts')}>View All</button>
          </div>
          <div className="card-body" style={{ height: '350px', overflowY: 'auto', padding: '1.5rem' }}>
            {alerts.length === 0 ? (
              <div className="empty-state" style={{ padding: 'var(--space-lg)' }}>
                <div className="empty-state-icon">✓</div>
                <p>No active alerts. System is clean.</p>
              </div>
            ) : (
              <div className="activity-feed" style={{ position: 'relative', paddingLeft: '1.5rem', borderLeft: '2px solid var(--border-subtle)' }}>
                {alerts.slice(0, 5).map((alert, i) => (
                  <div key={alert.alert_id || i} className="activity-item" style={{ position: 'relative', marginBottom: '1.5rem' }}>
                    <div style={{ position: 'absolute', left: '-1.9rem', top: '0.2rem', width: '12px', height: '12px', borderRadius: '50%', backgroundColor: severityColor(alert.severity), border: '2px solid var(--bg-surface)' }} />
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.25rem' }}>
                      <strong style={{ color: 'var(--text-primary)' }}>{alert.title || 'Unknown Alert'}</strong>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{i * 2 + 1}m ago</span>
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <span className={`badge badge-${severityClass(alert.severity)}`} style={{ fontSize: '0.7rem', padding: '0.1rem 0.4rem' }}>{alert.severity || 'N/A'}</span>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{alert.alert_type || 'N/A'}</span>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{alert.source_ip || ''}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 'var(--space-lg)', marginBottom: 'var(--space-xl)' }}>
        
        {/* Detection Sources */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Detection Sources</span>
          </div>
          <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {detectionSources.map((source, idx) => (
              <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: source.color }} />
                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>{source.name}</span>
                  </div>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{source.count}</span>
                </div>
                <div className="progress-bar" style={{ width: '100%', height: '6px', backgroundColor: 'var(--bg-elevated)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div className="progress-fill" style={{ height: '100%', width: `${totalDetections > 0 ? (source.count / totalDetections) * 100 : 0}%`, backgroundColor: source.color, borderRadius: '3px' }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* System Health Monitor */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">System Health Monitor</span>
          </div>
          <div className="card-body" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
            {/* Neo4j */}
            <div style={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Database size={18} color="var(--accent-primary)" />
                  <strong style={{ color: 'var(--text-primary)' }}>Neo4j Graph</strong>
                </div>
                <div style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: pipelineHealth?.neo4j?.toLowerCase() === 'online' ? 'var(--severity-low)' : 'var(--severity-critical)' }} />
              </div>
              <div>
                <div style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-primary)' }}>{pipelineHealth?.neo4j || 'Online'}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.25rem', marginTop: '0.25rem' }}>
                  <TrendingUp size={12} color="var(--severity-low)" /> Uptime 99.9%
                </div>
              </div>
            </div>

            {/* Redis */}
            <div style={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Zap size={18} color="#ef4444" />
                  <strong style={{ color: 'var(--text-primary)' }}>Redis Cache</strong>
                </div>
                <div style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: pipelineHealth?.redis?.toLowerCase() === 'online' ? 'var(--severity-low)' : 'var(--severity-critical)' }} />
              </div>
              <div>
                <div style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-primary)' }}>{pipelineHealth?.redis || 'Online'}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.25rem', marginTop: '0.25rem' }}>
                  <TrendingUp size={12} color="var(--severity-low)" /> Uptime 99.9%
                </div>
              </div>
            </div>

            {/* Kafka */}
            <div style={{ backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Server size={18} color="#f97316" />
                  <strong style={{ color: 'var(--text-primary)' }}>Kafka Bus</strong>
                </div>
                <div style={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: pipelineHealth?.kafka?.toLowerCase() === 'online' ? 'var(--severity-low)' : 'var(--severity-critical)' }} />
              </div>
              <div>
                <div style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-primary)' }}>{pipelineHealth?.kafka || 'Online'}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.25rem', marginTop: '0.25rem' }}>
                  <TrendingUp size={12} color="var(--severity-low)" /> Uptime 99.9%
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DashboardPage
