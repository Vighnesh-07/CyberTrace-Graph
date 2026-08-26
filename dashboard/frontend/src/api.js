const API_BASE = 'http://localhost:8000/api'

// Wrapper to inject JWT token
async function authFetch(url, options = {}) {
  const token = localStorage.getItem('auth_token');
  const headers = {
    ...options.headers,
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const response = await fetch(url, { ...options, headers });
  if (response.status === 401) {
    // Optional: handle token expiration by logging out
    localStorage.removeItem('auth_token');
    window.location.href = '/login';
  }
  return response;
}

export async function fetchAlerts(params = {}) {
  const url = new URL(`${API_BASE}/alerts`)
  Object.entries(params).forEach(([k, v]) => {
    if (v) url.searchParams.set(k, v)
  })
  const res = await authFetch(url)
  if (!res.ok) throw new Error(`Failed to fetch alerts: ${res.status}`)
  return res.json()
}

export async function fetchAlertById(alertId) {
  const res = await authFetch(`${API_BASE}/alerts/${alertId}`)
  if (!res.ok) throw new Error(`Alert not found: ${res.status}`)
  return res.json()
}

export async function updateAlertStatus(alertId, status) {
  const res = await authFetch(`${API_BASE}/alerts/${alertId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
  if (!res.ok) throw new Error(`Failed to update alert: ${res.status}`)
  return res.json()
}

export async function fetchGraphStats() {
  const res = await authFetch(`${API_BASE}/graph/stats`)
  if (!res.ok) throw new Error(`Failed to fetch graph stats: ${res.status}`)
  return res.json()
}

export async function fetchTopology(limit = 200) {
  const res = await authFetch(`${API_BASE}/graph/topology?limit=${limit}`)
  if (!res.ok) throw new Error(`Failed to fetch topology: ${res.status}`)
  return res.json()
}

export async function fetchDetections() {
  const res = await authFetch(`${API_BASE}/graph/detections`)
  if (!res.ok) throw new Error(`Failed to fetch detections: ${res.status}`)
  return res.json()
}

export async function fetchTimeline(ip) {
  const res = await authFetch(`${API_BASE}/graph/timeline/${ip}`)
  if (!res.ok) throw new Error(`Failed to fetch timeline: ${res.status}`)
  return res.json()
}

export async function fetchPipelineHealth() {
  const res = await authFetch(`${API_BASE}/pipeline/health`)
  if (!res.ok) throw new Error(`Failed to fetch health: ${res.status}`)
  return res.json()
}

export async function fetchPipelineStats() {
  const res = await authFetch(`${API_BASE}/pipeline/stats`)
  if (!res.ok) throw new Error(`Failed to fetch stats: ${res.status}`)
  return res.json()
}

export async function fetchAnalyticsSeverity() {
  const res = await fetch(`${API_BASE}/graph/analytics/severity-distribution`)
  if (!res.ok) throw new Error(`Failed to fetch severity analytics: ${res.status}`)
  return res.json()
}

export async function fetchAnalyticsTimeline() {
  const res = await fetch(`${API_BASE}/graph/analytics/alert-timeline`)
  if (!res.ok) throw new Error(`Failed to fetch timeline analytics: ${res.status}`)
  return res.json()
}

export async function fetchAnalyticsTechniques() {
  const res = await fetch(`${API_BASE}/graph/analytics/top-techniques`)
  if (!res.ok) throw new Error(`Failed to fetch top techniques: ${res.status}`)
  return res.json()
}
