import { useState, useEffect, useRef } from 'react'
import * as d3 from 'd3'
import { fetchTopology } from '../api'

const NODE_COLORS = {
  IPAddress: '#3b82f6',
  Domain: '#22c55e',
  Alert: '#ef4444',
  MITRETechnique: '#a855f7',
}

const NODE_RADIUS = {
  IPAddress: 8,
  Domain: 6,
  Alert: 10,
  MITRETechnique: 7,
}

function GraphPage() {
  const svgRef = useRef(null)
  const [loading, setLoading] = useState(true)
  const [nodeCount, setNodeCount] = useState(0)
  const [edgeCount, setEdgeCount] = useState(0)

  useEffect(() => {
    const loadGraph = async () => {
      try {
        const data = await fetchTopology(200)
        setNodeCount(data.nodes?.length || 0)
        setEdgeCount(data.edges?.length || 0)
        renderGraph(data)
      } catch (err) {
        console.error('Graph load error:', err)
      } finally {
        setLoading(false)
      }
    }
    loadGraph()
  }, [])

  const renderGraph = (data) => {
    if (!svgRef.current || !data.nodes || data.nodes.length === 0) return

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const width = svgRef.current.clientWidth
    const height = svgRef.current.clientHeight

    const g = svg.append('g')

    // Zoom
    const zoom = d3.zoom()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => g.attr('transform', event.transform))
    svg.call(zoom)

    // Build node ID map
    const nodeMap = new Map()
    data.nodes.forEach((n, i) => { nodeMap.set(n.id, i) })

    const links = data.edges
      .filter(e => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map(e => ({ source: e.source, target: e.target, type: e.type }))

    const simulation = d3.forceSimulation(data.nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(15))

    // Links
    const link = g.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#334155')
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0.6)

    // Nodes
    const node = g.append('g')
      .selectAll('g.node')
      .data(data.nodes)
      .join('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart()
          d.fx = d.x; d.fy = d.y
        })
        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0)
          d.fx = null; d.fy = null
        }))

    node.append('circle')
      .attr('r', d => NODE_RADIUS[d.label] || 6)
      .attr('fill', d => NODE_COLORS[d.label] || '#64748b')
      .attr('stroke', '#0a0e17')
      .attr('stroke-width', 1.5)

    node.append('title')
      .text(d => {
        const val = d.ip || d.address || d.name || d.domain || d.title || d.alert_type || ''
        return `${d.label}\n${val}`
      })

    // Labels
    const labels = node.append('text')
      .text(d => {
        const val = d.ip || d.address || d.name || d.domain || d.title || d.alert_type || ''
        if (d.label === 'Domain' && val.length > 25) {
           return val.substring(0, 10) + '...' + val.substring(val.length - 10)
        }
        return val.length > 25 ? val.substring(0, 22) + '...' : val
      })
      .attr('font-size', '9px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('fill', '#94a3b8')
      .attr('dx', 12)
      .attr('dy', 4)

    // Hover
    node.on('mouseover', function() {
      d3.select(this).select('circle').attr('stroke', '#e2e8f0').attr('stroke-width', 2.5)
      d3.select(this).select('text').attr('fill', '#ffffff').attr('font-weight', 'bold')
    }).on('mouseout', function(event, d) {
      d3.select(this).select('circle').attr('stroke', '#0a0e17').attr('stroke-width', 1.5)
      d3.select(this).select('text').attr('fill', '#94a3b8').attr('font-weight', 'normal')
    })

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y)
      node
        .attr('transform', d => `translate(${d.x},${d.y})`)
    })
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Attack Graph</h1>
        <p className="page-subtitle">{nodeCount} nodes · {edgeCount} edges · Drag to explore, scroll to zoom</p>
      </div>
      {loading ? (
        <div className="loading-container"><div className="spinner"></div>Loading graph topology...</div>
      ) : nodeCount === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">◎</div>
          <p>No graph data available. Run the attack simulator to generate data.</p>
        </div>
      ) : (
        <>
          <div style={{ display: 'flex', gap: '16px', marginBottom: '16px' }}>
            {Object.entries(NODE_COLORS).map(([label, color]) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: '#94a3b8' }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: color, display: 'inline-block' }}></span>
                {label}
              </div>
            ))}
          </div>
          <div className="graph-container">
            <svg ref={svgRef}></svg>
          </div>
        </>
      )}
    </div>
  )
}

export default GraphPage
