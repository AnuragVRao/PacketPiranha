import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { io } from 'socket.io-client'
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, RadialLinearScale,
  Filler, Tooltip, Legend
} from 'chart.js'
import { Line, Doughnut, Bar, Radar } from 'react-chartjs-2'
import './App.css'

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, RadialLinearScale,
  Filler, Tooltip, Legend
)

const socket = io('http://localhost:4242')

const FIELDS = [
  { key: 'layer1',              label: 'Layer 1'         },
  { key: 'layer2',              label: 'Layer 2'         },
  { key: 'layer3',              label: 'Layer 3'         },
  { key: 'layer4',              label: 'Layer 4'         },
  { key: 'sessionPresentation', label: 'Layer 5-6'       },
  { key: 'layer7',              label: 'Layer 7'         },
  { key: 'kernelMetadata',      label: 'Kernel Metadata' },
  { key: 'payload',             label: 'Payload'         },
]

const DEMO_DATA = {
  layer1: { interface: 'eth0', direction: 'ingress', packetsObserved: 10, layer: 'Physical' },
  layer2: {
    srcMAC: '00:1A:2B:3C:4D:5E', dstMAC: '10:22:33:44:55:66',
    uniqueSrcMACs: 1, ethType: '0x0800',
    framesCaptured: 10, avgFrameLen: 74, minFrameLen: 60, maxFrameLen: 74,
  },
  layer3: {
    srcIP: '1.1.1.1', dstIP: '192.168.1.42', ipVersion: 4, protocol: 'TCP',
    avgTTL: 57.3, minTTL: 55, maxTTL: 60, ttlVariance: 0.45,
    avgTotalLen: 44, dfSet: 10, mfSet: 0, fragmented: 0, uniqueIPIDs: 10,
    avgDSCP: 0, avgECN: 0,
    protocolCounts: { TCP: 75, UDP: 20, ICMP: 5 },
    topTalkers: { '192.168.1.42': 45, '1.1.1.1': 30, '10.0.0.5': 15, '8.8.8.8': 10 },
  },
  layer4: {
    protocol: 'TCP', dstPort: 12345, srcPort: 80,
    flagCounts: { SYN: 10, ACK: 10, RST: 0, FIN: 0, PSH: 0, URG: 0 },
    avgRTT_ms: 12.4, minRTT_ms: 10.1, maxRTT_ms: 15.9, rttJitter_ms: 1.8,
    avgWindowSize: 65535, minWindowSize: 65535, maxWindowSize: 65535,
    totalPackets: 10,
    topDstPorts: { 443: 50, 80: 30, 53: 15, 22: 5 },
    windowSizeSeries: [65535, 65535, 64240, 64240, 65000, 65535, 65535],
  },
  sessionPresentation: {
    flowID: '1.1.1.1 ↔ 192.168.1.42', sessionPackets: 10,
    sessionDuration_ms: 523, estimatedState: 'SYN_SENT → SYN_ACK received',
    encryptionHint: 'plaintext (port 80)', compressionHint: 'none detected',
    sessionStates: { 'ESTABLISHED': 60, 'SYN_SENT': 10, 'TIME_WAIT': 15, 'CLOSED': 5 },
    tlsVersions: { 'TLSv1.3': 70, 'TLSv1.2': 28, 'SSLv3': 2 },
  },
  layer7: {
    inferredProtocol: 'HTTP', description: 'Hypertext Transfer Protocol',
    destinationPort: 80, note: 'Application layer data not decoded (raw TCP SYN probes)',
    statusCodes: { '2xx (OK)': 65, '3xx (Redir)': 12, '4xx (Client)': 8, '5xx (Server)': 3 },
  },
  kernelMetadata: {
    captureMethod: 'eBPF TC ingress classifier', ebpfProgram: 'tc_ingress / SCHED_CLS',
    captureSpan_ms: 500, packetsMatched: 10,
    pid: 'n/a (ingress)', note: 'TC ingress — no process attribution',
    topProcesses: { 'nginx': 1500, 'node': 800, 'systemd-resolve': 300, 'sshd': 50 },
  },
  payload: {
    avgPayloadBytes: 0, minPayloadBytes: 0, maxPayloadBytes: 0,
    totalPayloadBytes: 0, note: 'SYN-ACK replies carry no application payload',
  },
}

// ── Gear geometry ─────────────────────────────────────────────────────────────
const N    = FIELDS.length
const CX   = 250, CY = 250
const OUTR = 148, INNR = 110, HOLR = 52, LBLR = 186
const FRAC = 0.55
const SLOW_SPEED = 0.0018
const LOAD_SPEED = 0.025

function pt(r, a) { return [CX + r * Math.cos(a), CY + r * Math.sin(a)] }

function buildGearPath() {
  const step = (2 * Math.PI) / N
  const half = (FRAC * step) / 2
  const verts = []
  for (let i = 0; i < N; i++) {
    const mid = -Math.PI / 2 + i * step
    verts.push(pt(OUTR, mid - half))
    verts.push(pt(OUTR, mid + half))
    verts.push(pt(INNR, mid + half))
    verts.push(pt(INNR, mid + step - half))
  }
  return verts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}`).join('') + 'Z'
}

const GEAR_PATH = buildGearPath()
const LABEL_POS = FIELDS.map((_, i) => pt(LBLR, -Math.PI / 2 + i * (2 * Math.PI / N)))

function buildToothSector(i) {
  const step = (2 * Math.PI) / N
  const half = (FRAC * step) / 2
  const a1 = -Math.PI / 2 + i * step - half
  const a2 = a1 + FRAC * step
  const r1 = INNR - 6, r2 = OUTR + 10
  const [ox1, oy1] = pt(r2, a1)
  const [ox2, oy2] = pt(r2, a2)
  const [ix1, iy1] = pt(r1, a1)
  const [ix2, iy2] = pt(r1, a2)
  const f = ([x, y]) => `${x.toFixed(2)},${y.toFixed(2)}`
  return [`M${f([ix1,iy1])}`,`L${f([ox1,oy1])}`,`A${r2},${r2},0,0,1,${f([ox2,oy2])}`,
          `L${f([ix2,iy2])}`,`A${r1},${r1},0,0,0,${f([ix1,iy1])}`,'Z'].join('')
}
const HIT_SECTORS = FIELDS.map((_, i) => buildToothSector(i))

// ── Chart defaults ────────────────────────────────────────────────────────────
const CHART_BASE = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 600, easing: 'easeInOutQuart' },
  plugins: {
    legend: {
      labels: {
        color: '#4d7a99',
        font: { family: "'Courier New', monospace", size: 10 },
        boxWidth: 10,
        padding: 10,
      }
    },
    tooltip: {
      backgroundColor: 'rgba(5,9,26,0.95)',
      borderColor: '#1a3f60',
      borderWidth: 1,
      titleColor: '#38bdf8',
      bodyColor: '#86efac',
      titleFont: { family: "'Courier New', monospace", size: 11 },
      bodyFont: { family: "'Courier New', monospace", size: 11 },
    }
  }
}

const AXIS_STYLE = {
  ticks: { color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } },
  grid:  { color: 'rgba(26,63,96,0.4)' },
  border:{ color: '#1a3f60' },
}

// ── Chart components ──────────────────────────────────────────────────────────

function RttLineChart({ data }) {
  if (!data?.avgRTT_ms) return <NoData label="No RTT data" />
  const { avgRTT_ms, minRTT_ms, maxRTT_ms, rttJitter_ms, totalPackets = 10 } = data

  // Use real per-packet RTT series if available, fall back to synthesised
  const isSynthesised = !data.rttSeries || data.rttSeries.filter(v => v != null).length < 2
  const rttSeries = useMemo(() => {
    const real = data.rttSeries?.filter(v => v != null)
    if (real && real.length >= 2) return real;
    return Array.from({ length: Math.max(totalPackets, 5) }, (_, i) => {
      const t = i / (Math.max(totalPackets, 5) - 1)
      const base = minRTT_ms + (maxRTT_ms - minRTT_ms) * (0.5 + 0.5 * Math.sin(t * Math.PI * 2.3))
      const jitter = (Math.random() - 0.5) * rttJitter_ms * 2
      return +(base + jitter).toFixed(2)
    })
  }, [data.rttSeries, totalPackets, minRTT_ms, maxRTT_ms, rttJitter_ms])

  const cfg = {
    ...CHART_BASE,
    scales: {
      x: { ...AXIS_STYLE, title: { display: true, text: 'packet #', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
      y: { ...AXIS_STYLE, title: { display: true, text: 'ms', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
    },
  }

  const chartData = {
    labels: rttSeries.map((_, i) => i + 1),
    datasets: [
      {
        label: 'RTT (ms)',
        data: rttSeries,
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56,189,248,0.08)',
        pointBackgroundColor: '#38bdf8',
        pointRadius: 3,
        pointHoverRadius: 5,
        tension: 0.4,
        fill: true,
        borderWidth: 2,
      },
      {
        label: `Avg ${avgRTT_ms}ms`,
        data: rttSeries.map(() => avgRTT_ms),
        borderColor: '#86efac',
        borderDash: [4, 4],
        pointRadius: 0,
        borderWidth: 1.5,
        fill: false,
      }
    ]
  }

  return (
    <div className="chart-block">
      <div className="chart-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        RTT Over Time
        <span style={{
          fontSize: 8, letterSpacing: 1, padding: '2px 6px', borderRadius: 3,
          background: isSynthesised ? 'rgba(251,191,36,0.12)' : 'rgba(134,239,172,0.12)',
          border: `1px solid ${isSynthesised ? '#fbbf24' : '#86efac'}`,
          color: isSynthesised ? '#fbbf24' : '#86efac',
        }}>
          {isSynthesised ? 'SYNTHESISED' : 'LIVE'}
        </span>
      </div>
      <div className="chart-canvas-wrap" style={{ height: 160 }}>
        <Line data={chartData} options={cfg} />
      </div>
      <div className="chart-stat-row">
        <StatPill label="min"    value={`${minRTT_ms}ms`} color="#86efac" />
        <StatPill label="avg"    value={`${avgRTT_ms}ms`} color="#38bdf8" />
        <StatPill label="max"    value={`${maxRTT_ms}ms`} color="#fbbf24" />
        <StatPill label="jitter" value={`${rttJitter_ms}ms`} color="#c084fc" />
      </div>
    </div>
  )
}

function InterPktDelayChart({ data }) {
  const delays = data?.interPktDelays_us
  if (!delays || delays.length < 1) return <NoData label="No inter-packet delay data" />

  const avg = +(delays.reduce((a, b) => a + b, 0) / delays.length).toFixed(2)
  const mn  = Math.min(...delays)
  const mx  = Math.max(...delays)

  const cfg = {
    ...CHART_BASE,
    scales: {
      x: { ...AXIS_STYLE, title: { display: true, text: 'gap #', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
      y: { ...AXIS_STYLE, title: { display: true, text: 'µs', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
    },
  }

  const chartData = {
    labels: delays.map((_, i) => i + 1),
    datasets: [
      {
        label: 'Inter-pkt delay (µs)',
        data: delays,
        borderColor: '#c084fc',
        backgroundColor: 'rgba(192,132,252,0.08)',
        pointBackgroundColor: '#c084fc',
        pointRadius: 3,
        pointHoverRadius: 5,
        tension: 0.3,
        fill: true,
        borderWidth: 2,
      },
      {
        label: `Avg ${avg}µs`,
        data: delays.map(() => avg),
        borderColor: '#fb923c',
        borderDash: [4, 4],
        pointRadius: 0,
        borderWidth: 1.5,
        fill: false,
      }
    ]
  }

  return (
    <div className="chart-block">
      <div className="chart-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        Inter-Packet Arrival Delay
        <span style={{
          fontSize: 8, letterSpacing: 1, padding: '2px 6px', borderRadius: 3,
          background: 'rgba(134,239,172,0.12)',
          border: '1px solid #86efac',
          color: '#86efac',
        }}>LIVE</span>
      </div>
      <div className="chart-canvas-wrap" style={{ height: 140 }}>
        <Line data={chartData} options={cfg} />
      </div>
      <div className="chart-stat-row">
        <StatPill label="min" value={`${mn}µs`}  color="#86efac" />
        <StatPill label="avg" value={`${avg}µs`} color="#c084fc" />
        <StatPill label="max" value={`${mx}µs`}  color="#fbbf24" />
      </div>
    </div>
  )
}

function FlagDonut({ data }) {
  if (!data?.flagCounts) return <NoData label="No flag data" />
  const { flagCounts } = data
  const flags  = ['SYN','ACK','RST','FIN','PSH','URG']
  const colors = ['#38bdf8','#86efac','#f87171','#fbbf24','#c084fc','#fb923c']
  const vals   = flags.map(f => flagCounts[f] || 0)

  const cfg = {
    ...CHART_BASE,
    cutout: '65%',
    plugins: {
      ...CHART_BASE.plugins,
      legend: { ...CHART_BASE.plugins.legend, position: 'right' },
    }
  }

  const total = vals.reduce((a, b) => a + b, 0)
  const dominant = flags[vals.indexOf(Math.max(...vals))]

  const chartData = {
    labels: flags,
    datasets: [{
      data: vals,
      backgroundColor: colors.map(c => c + 'cc'),
      borderColor: colors,
      borderWidth: 1.5,
      hoverBorderWidth: 2.5,
    }]
  }

  return (
    <div className="chart-block">
      <div className="chart-title">TCP Flag Distribution</div>
      <div className="chart-canvas-wrap" style={{ height: 160 }}>
        <Doughnut data={chartData} options={cfg} />
      </div>
      <div className="chart-stat-row">
        <StatPill label="total"    value={total}     color="#38bdf8" />
        <StatPill label="dominant" value={dominant}  color="#86efac" />
      </div>
    </div>
  )
}

function FrameSizeHistogram({ data }) {
  // Works for layer2 (frame sizes) or layer3 (packet sizes)
  const avg = data?.avgFrameLen ?? data?.avgTotalLen
  const min = data?.minFrameLen ?? data?.avgTotalLen
  const max = data?.maxFrameLen ?? data?.avgTotalLen
  if (avg == null) return <NoData label="No size data" />

  // Synthesise histogram buckets from stats
  const buckets = 8
  const range   = Math.max(max - min, 1)
  const step    = range / buckets
  const labels  = Array.from({ length: buckets }, (_, i) => `${Math.round(min + i * step)}`)
  const heights = labels.map((_, i) => {
    const centre = min + (i + 0.5) * step
    const sigma  = range / 4
    return Math.round(10 * Math.exp(-0.5 * ((centre - avg) / sigma) ** 2))
  })

  const cfg = {
    ...CHART_BASE,
    scales: {
      x: { ...AXIS_STYLE, title: { display: true, text: 'bytes', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
      y: { ...AXIS_STYLE, title: { display: true, text: 'count', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
    },
    plugins: { ...CHART_BASE.plugins, legend: { display: false } }
  }

  const chartData = {
    labels,
    datasets: [{
      label: 'Frames',
      data: heights,
      backgroundColor: labels.map((_, i) => {
        const t = i / (buckets - 1)
        return `rgba(${Math.round(56 + t * 130)},${Math.round(189 - t * 60)},${Math.round(248 - t * 90)},0.7)`
      }),
      borderColor: '#38bdf8',
      borderWidth: 1,
      borderRadius: 3,
    }]
  }

  return (
    <div className="chart-block">
      <div className="chart-title">Packet Size Distribution</div>
      <div className="chart-canvas-wrap" style={{ height: 150 }}>
        <Bar data={chartData} options={cfg} />
      </div>
      <div className="chart-stat-row">
        <StatPill label="min" value={`${min}B`}  color="#86efac" />
        <StatPill label="avg" value={`${avg}B`}  color="#38bdf8" />
        <StatPill label="max" value={`${max}B`}  color="#fbbf24" />
      </div>
    </div>
  )
}

function TtlGauge({ data }) {
  if (!data?.avgTTL) return <NoData label="No TTL data" />
  const { avgTTL, minTTL, maxTTL, ttlVariance } = data
  const startTTL  = avgTTL <= 64 ? 64 : 128
  const hops      = Math.round(startTTL - avgTTL)
  const pct       = (avgTTL / startTTL) * 100

  // Radial gauge via canvas-drawn arc inside SVG-like CSS
  const gaugeColor = pct > 70 ? '#86efac' : pct > 40 ? '#fbbf24' : '#f87171'

  const cfg = {
    ...CHART_BASE,
    scales: {
      x: { ...AXIS_STYLE, title: { display: true, text: 'TTL value', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
      y: { ...AXIS_STYLE, title: { display: true, text: 'count', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
    },
    plugins: { ...CHART_BASE.plugins, legend: { display: false } }
  }

  const ttlRange = Array.from({ length: 12 }, (_, i) => minTTL - 2 + i)
  const ttlCounts = ttlRange.map(v => {
    const sigma = (maxTTL - minTTL) / 3 + 0.1
    return Math.max(0, Math.round(8 * Math.exp(-0.5 * ((v - avgTTL) / sigma) ** 2)))
  })

  const chartData = {
    labels: ttlRange.map(String),
    datasets: [{
      data: ttlCounts,
      backgroundColor: ttlRange.map(v =>
        Math.abs(v - avgTTL) < 1 ? gaugeColor + 'cc' : 'rgba(56,189,248,0.25)'
      ),
      borderColor: ttlRange.map(v =>
        Math.abs(v - avgTTL) < 1 ? gaugeColor : '#1a3f60'
      ),
      borderWidth: 1,
      borderRadius: 3,
    }]
  }

  return (
    <div className="chart-block">
      <div className="chart-title">TTL Distribution</div>
      {/* Arc gauge */}
      <div className="ttl-gauge-wrap">
        <svg viewBox="0 0 120 70" className="ttl-arc-svg">
          <path d="M10,60 A50,50,0,0,1,110,60" fill="none" stroke="#1a3f60" strokeWidth="8" strokeLinecap="round"/>
          <path d="M10,60 A50,50,0,0,1,110,60" fill="none"
            stroke={gaugeColor}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${pct * 1.57} 999`}
            style={{ transition: 'stroke-dasharray 0.8s cubic-bezier(0.4,0,0.2,1)' }}
          />
          <text x="60" y="55" textAnchor="middle" fill={gaugeColor}
            style={{ fontFamily: "'Courier New',monospace", fontSize: 14, fontWeight: 'bold' }}>
            {avgTTL}
          </text>
          <text x="60" y="65" textAnchor="middle" fill="#4d7a99"
            style={{ fontFamily: "'Courier New',monospace", fontSize: 7 }}>
            avg TTL
          </text>
        </svg>
      </div>
      <div className="chart-canvas-wrap" style={{ height: 110 }}>
        <Bar data={chartData} options={cfg} />
      </div>
      <div className="chart-stat-row">
        <StatPill label="min"      value={minTTL}       color="#86efac" />
        <StatPill label="max"      value={maxTTL}       color="#fbbf24" />
        <StatPill label="~hops"    value={hops}         color="#38bdf8" />
        <StatPill label="variance" value={ttlVariance}  color="#c084fc" />
      </div>
    </div>
  )
}

function LayerRadar({ allData }) {
  const layers = [
    { key: 'layer1',              label: 'L1 Phys',    score: d => d?.packetsObserved  ? 80  : 0 },
    { key: 'layer2',              label: 'L2 Link',    score: d => d?.framesCaptured   ? 90  : 0 },
    { key: 'layer3',              label: 'L3 Net',     score: d => d?.avgTTL           ? 85  : 0 },
    { key: 'layer4',              label: 'L4 Trans',   score: d => d?.avgRTT_ms        ? 95  : 0 },
    { key: 'sessionPresentation', label: 'L5-6 Sess',  score: d => d?.sessionPackets   ? 75  : 0 },
    { key: 'layer7',              label: 'L7 App',     score: d => d?.inferredProtocol ? 60  : 0 },
    { key: 'kernelMetadata',      label: 'Kernel',     score: d => d?.packetsMatched   ? 100 : 0 },
    { key: 'payload',             label: 'Payload',    score: d => d?.totalPayloadBytes > 0 ? 70 : 20 },
  ]

  const scores = layers.map(l => l.score(allData?.[l.key] ?? DEMO_DATA[l.key]))

  const cfg = {
    ...CHART_BASE,
    scales: {
      r: {
        min: 0, max: 100,
        ticks: { display: false, stepSize: 25 },
        grid:  { color: 'rgba(26,63,96,0.5)' },
        angleLines: { color: 'rgba(26,63,96,0.6)' },
        pointLabels: {
          color: '#4d7a99',
          font: { family: "'Courier New',monospace", size: 9 }
        }
      }
    },
  }

  const chartData = {
    labels: layers.map(l => l.label),
    datasets: [{
      label: 'Data Quality',
      data: scores,
      backgroundColor: 'rgba(56,189,248,0.1)',
      borderColor: '#38bdf8',
      pointBackgroundColor: scores.map(s => s > 80 ? '#86efac' : s > 50 ? '#38bdf8' : '#f87171'),
      pointRadius: 4,
      borderWidth: 2,
      fill: true,
    }]
  }

  const covered = scores.filter(s => s > 0).length
  const avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)

  return (
    <div className="chart-block">
      <div className="chart-title">Layer Coverage Radar</div>
      <div className="chart-canvas-wrap" style={{ height: 200 }}>
        <Radar data={chartData} options={cfg} />
      </div>
      <div className="chart-stat-row">
        <StatPill label="layers"  value={`${covered}/8`}  color="#38bdf8" />
        <StatPill label="quality" value={`${avgScore}%`}  color="#86efac" />
      </div>
    </div>
  )
}

function SimpleHorizontalBar({ title, dataObj, color, xLabel }) {
  if (!dataObj) return <NoData label={`No ${title} data`} />
  const labels = Object.keys(dataObj)
  const vals = Object.values(dataObj)
  const cfg = {
    ...CHART_BASE,
    indexAxis: 'y',
    scales: {
      x: { ...AXIS_STYLE, title: { display: true, text: xLabel, color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
      y: { ...AXIS_STYLE, ticks: { ...AXIS_STYLE.ticks, autoSkip: false } },
    },
    plugins: { ...CHART_BASE.plugins, legend: { display: false } }
  }
  const chartData = {
    labels,
    datasets: [{ data: vals, backgroundColor: `${color}aa`, borderColor: color, borderWidth: 1, borderRadius: 2 }]
  }
  return (
    <div className="chart-block">
      <div className="chart-title">{title}</div>
      <div className="chart-canvas-wrap" style={{ height: 150 }}>
        <Bar data={chartData} options={cfg} />
      </div>
    </div>
  )
}

function SimpleBar({ title, dataObj, color, yLabel }) {
  if (!dataObj) return <NoData label={`No ${title} data`} />
  const labels = Object.keys(dataObj)
  const vals = Object.values(dataObj)
  const cfg = {
    ...CHART_BASE,
    scales: {
      x: { ...AXIS_STYLE },
      y: { ...AXIS_STYLE, title: { display: true, text: yLabel, color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
    },
    plugins: { ...CHART_BASE.plugins, legend: { display: false } }
  }
  const chartData = {
    labels,
    datasets: [{ data: vals, backgroundColor: `${color}aa`, borderColor: color, borderWidth: 1, borderRadius: 2 }]
  }
  return (
    <div className="chart-block">
      <div className="chart-title">{title}</div>
      <div className="chart-canvas-wrap" style={{ height: 150 }}>
        <Bar data={chartData} options={cfg} />
      </div>
    </div>
  )
}

function SimpleDoughnut({ title, dataObj, colors }) {
  if (!dataObj) return <NoData label={`No ${title} data`} />
  const labels = Object.keys(dataObj)
  const vals = Object.values(dataObj)
  const cfg = {
    ...CHART_BASE,
    cutout: '55%',
    plugins: { ...CHART_BASE.plugins, legend: { ...CHART_BASE.plugins.legend, position: 'right' } }
  }
  const chartData = {
    labels,
    datasets: [{ data: vals, backgroundColor: colors.map(c => c + 'cc'), borderColor: colors, borderWidth: 1.5, hoverBorderWidth: 2.5 }]
  }
  return (
    <div className="chart-block">
      <div className="chart-title">{title}</div>
      <div className="chart-canvas-wrap" style={{ height: 160 }}>
        <Doughnut data={chartData} options={cfg} />
      </div>
    </div>
  )
}

function WindowSizeLineChart({ data }) {
  const series = data?.windowSizeSeries
  if (!series || series.length < 2) return <NoData label="No window size data" />
  const avg = Math.round(series.reduce((a, b) => a + b, 0) / series.length)
  const cfg = {
    ...CHART_BASE,
    scales: {
      x: { ...AXIS_STYLE, title: { display: true, text: 'time', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
      y: { ...AXIS_STYLE, title: { display: true, text: 'bytes', color: '#4d7a99', font: { family: "'Courier New', monospace", size: 9 } } },
    },
  }
  const chartData = {
    labels: series.map((_, i) => i + 1),
    datasets: [
      {
        label: 'Window Size', data: series, borderColor: '#f472b6', backgroundColor: 'rgba(244,114,182,0.08)',
        pointBackgroundColor: '#f472b6', pointRadius: 3, tension: 0.2, fill: true, borderWidth: 2,
      },
      {
        label: `Avg ${avg}`, data: series.map(() => avg), borderColor: '#fbbf24', borderDash: [4, 4], pointRadius: 0, borderWidth: 1.5, fill: false,
      }
    ]
  }
  return (
    <div className="chart-block">
      <div className="chart-title">TCP Window Size Trend</div>
      <div className="chart-canvas-wrap" style={{ height: 160 }}>
        <Line data={chartData} options={cfg} />
      </div>
      <div className="chart-stat-row">
        <StatPill label="avg size" value={`${avg}B`} color="#f472b6" />
      </div>
    </div>
  )
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function StatPill({ label, value, color }) {
  return (
    <div className="stat-pill">
      <span className="stat-pill-label">{label}</span>
      <span className="stat-pill-val" style={{ color }}>{value}</span>
    </div>
  )
}

function NoData({ label }) {
  return <div className="no-data-msg">{label}</div>
}

function KVList({ data }) {
  if (!data || !Object.keys(data).length) return <span className="kv-empty">No data</span>
  return (
    <div className="panel-kv">
      {Object.entries(data).map(([k, v]) => (
        <div key={k} className="kv-row">
          <span className="kv-key">{k}</span>
          <span className="kv-val">{String(v)}</span>
        </div>
      ))}
    </div>
  )
}

// ── Tabbed panel content ──────────────────────────────────────────────────────
function LayerPanelTabbed({ fieldKey, data, allData }) {
  const [tab, setTab] = useState('stats')

  const hasCharts = ['layer3','layer4','layer2','sessionPresentation','layer7','kernelMetadata'].includes(fieldKey) || fieldKey === 'overview'
  const tabs = hasCharts ? ['stats','charts'] : ['stats']

  // Flat KV data (strip nested objects)
  const plain = data
    ? Object.fromEntries(Object.entries(data).filter(([, v]) => typeof v !== 'object'))
    : null

  return (
    <div className="tabbed-panel">
      {tabs.length > 1 && (
        <div className="tab-bar">
          {tabs.map(t => (
            <button
              key={t}
              className={`tab-btn${tab === t ? ' tab-btn-on' : ''}`}
              onClick={() => setTab(t)}>
              {t.toUpperCase()}
            </button>
          ))}
        </div>
      )}

      <div className="tab-content">
        {tab === 'stats' && (
          <>
            {plain && Object.keys(plain).length > 0
              ? <KVList data={plain} />
              : <span className="kv-empty">No scalar data for this layer</span>
            }
            {/* Layer4 special: flag counts as KV */}
            {fieldKey === 'layer4' && data?.flagCounts && (
              <KVList data={data.flagCounts} />
            )}
          </>
        )}

        {tab === 'charts' && (
          <div className="charts-scroll">
            {fieldKey === 'layer4' && (
              <>
                <SimpleHorizontalBar title="Top Destination Ports" dataObj={data?.topDstPorts} color="#38bdf8" xLabel="packets" />
                <WindowSizeLineChart data={data} />
                <RttLineChart data={data} />
                <InterPktDelayChart data={data} />
                <FlagDonut data={data} />
              </>
            )}
            {fieldKey === 'layer2' && (
              <FrameSizeHistogram data={data} />
            )}
            {fieldKey === 'layer3' && (
              <>
                <SimpleDoughnut title="Protocol Distribution" dataObj={data?.protocolCounts} colors={['#38bdf8','#86efac','#f87171','#fbbf24']} />
                <SimpleHorizontalBar title="Top Talkers (IPs)" dataObj={data?.topTalkers} color="#c084fc" xLabel="packets" />
                <TtlGauge data={data} />
                <FrameSizeHistogram data={data} />
              </>
            )}
            {fieldKey === 'sessionPresentation' && (
              <>
                <SimpleDoughnut title="Connection State Distribution" dataObj={data?.sessionStates} colors={['#86efac','#f87171','#fbbf24','#38bdf8']} />
                <SimpleBar title="TLS Version Breakdown" dataObj={data?.tlsVersions} color="#fb923c" yLabel="count" />
              </>
            )}
            {fieldKey === 'layer7' && (
              <SimpleBar title="HTTP Status Code Breakdown" dataObj={data?.statusCodes} color="#38bdf8" yLabel="requests" />
            )}
            {fieldKey === 'kernelMetadata' && (
              <SimpleHorizontalBar title="Top Processes by Packet Count" dataObj={data?.topProcesses} color="#f87171" xLabel="packets" />
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Overview: all charts when no tooth selected ───────────────────────────────
function OverviewPanel({ allData }) {
  const [tab, setTab] = useState('radar')
  const tabs = ['radar','proto','ports','states','http','procs']

  return (
    <div className="tabbed-panel">
      <div className="tab-bar tab-bar-sm" style={{ flexWrap: 'wrap' }}>
        {tabs.map(t => (
          <button
            key={t}
            className={`tab-btn tab-btn-sm${tab === t ? ' tab-btn-on' : ''}`}
            onClick={() => setTab(t)}>
            {t.toUpperCase()}
          </button>
        ))}
      </div>
      <div className="tab-content">
        <div className="charts-scroll">
          {tab === 'radar'  && <LayerRadar allData={allData} />}
          {tab === 'proto'  && (
            <>
              <SimpleDoughnut title="Protocol Distribution" dataObj={(allData ?? DEMO_DATA).layer3?.protocolCounts} colors={['#38bdf8','#86efac','#f87171','#fbbf24']} />
              <SimpleHorizontalBar title="Top Talkers (IPs)" dataObj={(allData ?? DEMO_DATA).layer3?.topTalkers} color="#c084fc" xLabel="packets" />
            </>
          )}
          {tab === 'ports'  && (
            <>
              <SimpleHorizontalBar title="Top Destination Ports" dataObj={(allData ?? DEMO_DATA).layer4?.topDstPorts} color="#38bdf8" xLabel="packets" />
              <WindowSizeLineChart data={(allData ?? DEMO_DATA).layer4} />
            </>
          )}
          {tab === 'states' && (
            <>
              <SimpleDoughnut title="Connection State Distribution" dataObj={(allData ?? DEMO_DATA).sessionPresentation?.sessionStates} colors={['#86efac','#f87171','#fbbf24','#38bdf8']} />
              <SimpleBar title="TLS Version Breakdown" dataObj={(allData ?? DEMO_DATA).sessionPresentation?.tlsVersions} color="#fb923c" yLabel="count" />
            </>
          )}
          {tab === 'http'   && <SimpleBar title="HTTP Status Code Breakdown" dataObj={(allData ?? DEMO_DATA).layer7?.statusCodes} color="#38bdf8" yLabel="requests" />}
          {tab === 'procs'  && <SimpleHorizontalBar title="Top Processes by Packet Count" dataObj={(allData ?? DEMO_DATA).kernelMetadata?.topProcesses} color="#f87171" xLabel="packets" />}
        </div>
      </div>
    </div>
  )
}

// ── Stats full-page view ───────────────────────────────────────────────────────
function StatsPage({ packet, onBack }) {
// Merge per-key: use live value if present, otherwise fall back to DEMO_DATA for that key
  const data = packet
    ? Object.fromEntries(
        Object.keys(DEMO_DATA).map(k => [k, packet[k] ?? DEMO_DATA[k]])
      )
    : DEMO_DATA
  const isLive = !!packet


  const SECTION_COLORS = [
    '#38bdf8', '#86efac', '#c084fc', '#f472b6',
    '#fbbf24', '#fb923c', '#f87171', '#34d399'
  ]

  return (
    <div className="stats-page">
      {/* Header */}
      <div className="stats-header">
        <button className="back-btn stats-back-btn" onClick={onBack}>← BACK</button>
        <div className="stats-title">
          <span className="stats-title-icon">⬡</span> PACKET ANALYTICS
        </div>
        <div className={`stats-badge ${isLive ? 'stats-badge-live' : 'stats-badge-demo'}`}>
          {isLive ? '● LIVE DATA' : '○ LIVE DATA'}
        </div>
      </div>

      {/* Grid */}
      <div className="stats-grid">

        {/* Layer Radar – full width */}
        <div className="stats-card stats-card-wide">
          <div className="stats-card-section">Overview · Layer Coverage</div>
          <LayerRadar allData={data} />
        </div>

        {/* Protocol Distribution */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[0] }}>L3 · Protocol</div>
          <SimpleDoughnut
            title="Protocol Distribution"
            dataObj={data.layer3?.protocolCounts}
            colors={['#38bdf8','#86efac','#f87171','#fbbf24']}
          />
        </div>

        {/* Top Talkers */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[1] }}>L3 · Top Talkers</div>
          <SimpleHorizontalBar
            title="Top Talkers (IPs)"
            dataObj={data.layer3?.topTalkers}
            color="#c084fc"
            xLabel="packets"
          />
        </div>

        {/* TTL Distribution */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[2] }}>L3 · TTL</div>
          <TtlGauge data={data.layer3} />
        </div>

        {/* Packet Size */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[3] }}>L2/L3 · Frame Size</div>
          <FrameSizeHistogram data={data.layer2 ?? data.layer3} />
        </div>

        {/* TCP Flags */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[4] }}>L4 · TCP Flags</div>
          <FlagDonut data={data.layer4} />
        </div>

        {/* Top Dst Ports */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[5] }}>L4 · Dest Ports</div>
          <SimpleHorizontalBar
            title="Top Destination Ports"
            dataObj={data.layer4?.topDstPorts}
            color="#38bdf8"
            xLabel="packets"
          />
        </div>

        {/* RTT – wide */}
        <div className="stats-card stats-card-wide">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[6] }}>L4 · Round-Trip Time</div>
          <RttLineChart data={data.layer4} />
        </div>

        {/* Window Size – wide */}
        <div className="stats-card stats-card-wide">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[7] }}>L4 · TCP Window Size</div>
          <WindowSizeLineChart data={data.layer4} />
        </div>

        {/* Connection States */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[0] }}>L5-6 · Session States</div>
          <SimpleDoughnut
            title="Connection State Distribution"
            dataObj={data.sessionPresentation?.sessionStates}
            colors={['#86efac','#f87171','#fbbf24','#38bdf8']}
          />
        </div>

        {/* TLS Versions */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[1] }}>L5-6 · TLS Versions</div>
          <SimpleBar
            title="TLS Version Breakdown"
            dataObj={data.sessionPresentation?.tlsVersions}
            color="#fb923c"
            yLabel="count"
          />
        </div>

        {/* HTTP Status */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[2] }}>L7 · HTTP Status Codes</div>
          <SimpleBar
            title="HTTP Status Code Breakdown"
            dataObj={data.layer7?.statusCodes}
            color="#38bdf8"
            yLabel="requests"
          />
        </div>

        {/* Top Processes */}
        <div className="stats-card">
          <div className="stats-card-section" style={{ color: SECTION_COLORS[3] }}>Kernel · Top Processes</div>
          <SimpleHorizontalBar
            title="Top Processes by Packet Count"
            dataObj={data.kernelMetadata?.topProcesses}
            color="#f87171"
            xLabel="packets"
          />
        </div>

      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────
export default function App() {
  const [view, setView] = useState('main') // 'main' | 'stats'
  const [packet,   setPacket]   = useState(null)
  const [status,   setStatus]   = useState('Click CAPTURE to begin')
  const [loading,  setLoading]  = useState(false)
  const [selected, setSelected] = useState(null)
  const [hovered,  setHovered]  = useState(null)
  const [panelOpen, setPanelOpen] = useState(false)

  const gearGRef    = useRef(null)
  const labelRefs   = useRef([])
  const rotRef      = useRef(0)
  const targetRef   = useRef(null)
  const selectedRef = useRef(null)
  const loadingRef  = useRef(false)
  const rafRef      = useRef(null)

  useEffect(() => { loadingRef.current = loading },  [loading])
  useEffect(() => { selectedRef.current = selected }, [selected])

  useEffect(() => {
    function animate() {
      if (targetRef.current !== null) {
        const diff = targetRef.current - rotRef.current
        if (Math.abs(diff) < 0.002) {
          rotRef.current = targetRef.current
          targetRef.current = null
        } else {
          rotRef.current += diff * 0.08
        }
      } else if (selectedRef.current === null) {
        rotRef.current += loadingRef.current ? LOAD_SPEED : SLOW_SPEED
      }
      const deg = (rotRef.current * 180) / Math.PI
      if (gearGRef.current)
        gearGRef.current.setAttribute('transform', `rotate(${deg}, ${CX}, ${CY})`)
      labelRefs.current.forEach((el, idx) => {
        if (!el) return
        const [lx, ly] = LABEL_POS[idx]
        el.setAttribute('transform', `rotate(${-deg}, ${lx.toFixed(2)}, ${ly.toFixed(2)})`)
      })
      rafRef.current = requestAnimationFrame(animate)
    }
    rafRef.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(rafRef.current)
  }, [])

  useEffect(() => {
    const onStatus = ({ message }) => setStatus(message)
    const onData   = d => { setPacket(d); setLoading(false); setStatus('Capture complete') }
    const onError  = ({ message }) => { setStatus(`Error: ${message}`); setLoading(false) }
    socket.on('status',      onStatus)
    socket.on('packet_data', onData)
    socket.on('error',       onError)
    return () => {
      socket.off('status', onStatus)
      socket.off('packet_data', onData)
      socket.off('error', onError)
    }
  }, [])

  function startCapture() {
    if (loading) return
    setLoading(true)
    setPacket(null)
    setSelected(null)
    selectedRef.current = null
    targetRef.current   = null
    setStatus('Starting capture…')
    socket.emit('start_capture', { destIp: '1.1.1.1', dstPort: 80, count: 10 })
  }

  function pickTooth(i) {
    setSelected(prev => {
      if (prev === i) {
        targetRef.current = null
        setPanelOpen(false)
        return null
      }
      const step    = (2 * Math.PI) / N
      const neutral = -Math.PI / 2 + i * step
      let tgt       = -neutral
      while (tgt < rotRef.current) tgt += 2 * Math.PI
      targetRef.current = tgt
      setPanelOpen(true)
      return i
    })
  }

  function openOverview() {
    setPanelOpen(true)
    setSelected(null)
    selectedRef.current = null
    targetRef.current   = null
  }

  const moved     = panelOpen
  const selField  = selected !== null ? FIELDS[selected] : null
  const layerData = selField
    ? (packet ? packet[selField.key] : null) ?? DEMO_DATA[selField.key] ?? null
    : null

  if (view === 'stats') {
    return <StatsPage packet={packet} onBack={() => setView('main')} />
  }

  return (
    <div className="container">
      {/* ── Gear ── */}
      <div className={`gear-wrap${moved ? ' moved' : ''}`}>
        <svg viewBox="0 0 500 500" className="gear-svg">
          <g ref={gearGRef}>
            <path d={GEAR_PATH} className="gear-body" />
            <circle cx={CX} cy={CY} r={HOLR} className="gear-hole" />
            {HIT_SECTORS.map((d, i) => (
              <path key={`hit-${i}`} d={d} fill="transparent" stroke="none"
                style={{ cursor: 'pointer' }}
                onClick={() => pickTooth(i)}
                onMouseEnter={() => setHovered(i)}
                onMouseLeave={() => setHovered(null)} />
            ))}
            {FIELDS.map((f, i) => {
              const [lx, ly] = LABEL_POS[i]
              const active   = selected === i || hovered === i
              const spaceIdx = f.label.lastIndexOf(' ')
              const lines    = spaceIdx !== -1
                ? [f.label.slice(0, spaceIdx), f.label.slice(spaceIdx + 1)]
                : [f.label]
              return (
                <text key={i} ref={el => { labelRefs.current[i] = el }}
                  x={lx.toFixed(2)} y={ly.toFixed(2)}
                  textAnchor="middle" dominantBaseline="middle"
                  fontSize={active ? 12.5 : 11}
                  className={`lbl${active ? ' lbl-on' : ''}`}
                  style={{ cursor: 'pointer' }}
                  onClick={() => pickTooth(i)}
                  onMouseEnter={() => setHovered(i)}
                  onMouseLeave={() => setHovered(null)}>
                  {lines.length > 1 ? (
                    <>
                      <tspan x={lx.toFixed(2)} dy="-0.65em">{lines[0]}</tspan>
                      <tspan x={lx.toFixed(2)} dy="1.3em">{lines[1]}</tspan>
                    </>
                  ) : f.label}
                </text>
              )
            })}
          </g>

          {/* Centre: click to capture, shift+click for overview */}
          <circle cx={CX} cy={CY} r={HOLR - 2} fill="transparent" className="centre-hit"
            onClick={startCapture}
            onContextMenu={e => { e.preventDefault(); openOverview() }} />
          <text x={CX} y={CY} textAnchor="middle" dominantBaseline="middle"
            fontSize={loading ? 14 : 17}
            className={`ctxt${loading ? ' ctxt-pulse' : ''}`}
            onClick={startCapture}>
            {loading ? '···' : 'CAPTURE'}
          </text>
        </svg>

        {/* Stats page shortcut */}
        <button className="overview-btn" onClick={() => setView('stats')} title="Open full stats dashboard">
          ⬡ STATS
        </button>
      </div>

      {/* ── Info panel ── */}
      <div className={`panel${moved ? ' panel-on' : ''}`}>
        <button className="back-btn"
          onClick={() => {
            setSelected(null)
            selectedRef.current = null
            targetRef.current   = null
            setPanelOpen(false)
          }}>
          ← Back
        </button>

        {panelOpen && (
          <>
            <div className="panel-title">
              {selField ? selField.label : 'Overview · All Layers'}
            </div>

            {packet?._meta && (
              <div className="agg-badge">
                {packet._meta.totalFramesCaptured} packets · {packet._meta.captureTarget}
              </div>
            )}

            <div className="panel-kv-wrap">
              {selField
                ? <LayerPanelTabbed
                    fieldKey={selField.key}
                    data={layerData}
                    allData={packet ?? DEMO_DATA}
                  />
                : <OverviewPanel allData={packet ?? DEMO_DATA} />
              }
            </div>
          </>
        )}

        <div className="panel-status">{status}</div>
      </div>
    </div>
  )
}