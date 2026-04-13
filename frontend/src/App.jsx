import { useState, useEffect, useRef } from 'react'
import { io } from 'socket.io-client'
import './App.css'

const socket = io('http://localhost:4242')

// ── OSI layer fields shown as gear teeth ──────────────────────────────────────
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

// ── Demo placeholder (shown until real capture) ───────────────────────────────
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
  },
  layer4: {
    protocol: 'TCP', dstPort: 12345, srcPort: 80,
    flagCounts: { SYN: 10, ACK: 10, RST: 0, FIN: 0, PSH: 0, URG: 0 },
    avgRTT_ms: 12.4, minRTT_ms: 10.1, maxRTT_ms: 15.9, rttJitter_ms: 1.8,
    avgWindowSize: 65535, minWindowSize: 65535, maxWindowSize: 65535,
    totalPackets: 10,
  },
  sessionPresentation: {
    flowID: '1.1.1.1 ↔ 192.168.1.42', sessionPackets: 10,
    sessionDuration_ms: 523, estimatedState: 'SYN_SENT → SYN_ACK received',
    encryptionHint: 'plaintext (port 80)', compressionHint: 'none detected',
  },
  layer7: {
    inferredProtocol: 'HTTP', description: 'Hypertext Transfer Protocol',
    destinationPort: 80, note: 'Application layer data not decoded (raw TCP SYN probes)',
  },
  kernelMetadata: {
    captureMethod: 'eBPF TC ingress classifier', ebpfProgram: 'tc_ingress / SCHED_CLS',
    captureSpan_ms: 500, packetsMatched: 10,
    pid: 'n/a (ingress)', note: 'TC ingress — no process attribution',
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

// ── Specialised sub-renderers ─────────────────────────────────────────────────

function FlagBar({ counts }) {
  if (!counts) return null
  const flags = ['SYN','ACK','RST','FIN','PSH','URG']
  const maxVal = Math.max(...Object.values(counts), 1)
  const colors = { SYN:'#38bdf8', ACK:'#86efac', RST:'#f87171', FIN:'#fbbf24', PSH:'#c084fc', URG:'#fb923c' }
  return (
    <div className="flag-chart">
      <div className="flag-chart-title">TCP Flag Distribution</div>
      {flags.map(fl => (
        <div key={fl} className="flag-row">
          <span className="flag-name">{fl}</span>
          <div className="flag-bar-bg">
            <div className="flag-bar-fill"
              style={{ width: `${(counts[fl] || 0) / maxVal * 100}%`, background: colors[fl] }} />
          </div>
          <span className="flag-count">{counts[fl] || 0}</span>
        </div>
      ))}
    </div>
  )
}

function RttStat({ avg, min, max, jitter }) {
  if (avg == null) return null
  return (
    <div className="rtt-stat">
      <div className="rtt-stat-title">RTT Statistics (ms)</div>
      <div className="rtt-grid">
        <div className="rtt-cell"><span className="rtt-label">avg</span><span className="rtt-val">{avg}</span></div>
        <div className="rtt-cell"><span className="rtt-label">min</span><span className="rtt-val">{min}</span></div>
        <div className="rtt-cell"><span className="rtt-label">max</span><span className="rtt-val">{max}</span></div>
        <div className="rtt-cell"><span className="rtt-label">jitter</span><span className="rtt-val">{jitter}</span></div>
      </div>
    </div>
  )
}

function TtlBar({ avg, min, max }) {
  if (avg == null) return null
  // TTL starts at 64 or 128, infer hops
  const startTTL = avg <= 64 ? 64 : 128
  const hops = Math.round(startTTL - avg)
  const pct  = Math.min(100, (avg / startTTL) * 100)
  return (
    <div className="ttl-stat">
      <div className="rtt-stat-title">TTL Analysis</div>
      <div className="ttl-bar-wrap">
        <div className="ttl-bar-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="ttl-row-nums">
        <span>min {min}</span>
        <span>avg {avg}</span>
        <span>max {max}</span>
        <span>~{hops} hops</span>
      </div>
    </div>
  )
}

// ── Layer-specific panel content ──────────────────────────────────────────────
function LayerPanel({ fieldKey, data }) {
  if (!data) return <span className="kv-empty">No data captured yet</span>

  if (fieldKey === 'layer4') {
    const { flagCounts, avgRTT_ms, minRTT_ms, maxRTT_ms, rttJitter_ms, ...rest } = data
    const plain = Object.fromEntries(
      Object.entries(rest).filter(([, v]) => typeof v !== 'object')
    )
    return (
      <>
        <KVList data={plain} />
        <FlagBar counts={flagCounts} />
        <RttStat avg={avgRTT_ms} min={minRTT_ms} max={maxRTT_ms} jitter={rttJitter_ms} />
      </>
    )
  }

  if (fieldKey === 'layer3') {
    const { avgTTL, minTTL, maxTTL, ...rest } = data
    const plain = Object.fromEntries(
      Object.entries(rest).filter(([, v]) => typeof v !== 'object')
    )
    return (
      <>
        <KVList data={plain} />
        <TtlBar avg={avgTTL} min={minTTL} max={maxTTL} />
      </>
    )
  }

  // Default: flat KV
  const plain = Object.fromEntries(
    Object.entries(data).filter(([, v]) => typeof v !== 'object')
  )
  return <KVList data={plain} />
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

// ── Main component ────────────────────────────────────────────────────────────
export default function App() {
  const [packet,   setPacket]   = useState(null)
  const [status,   setStatus]   = useState('Click CAPTURE to begin')
  const [loading,  setLoading]  = useState(false)
  const [selected, setSelected] = useState(null)
  const [hovered,  setHovered]  = useState(null)

  const gearGRef    = useRef(null)
  const labelRefs   = useRef([])
  const rotRef      = useRef(0)
  const targetRef   = useRef(null)
  const selectedRef = useRef(null)
  const loadingRef  = useRef(false)
  const rafRef      = useRef(null)

  useEffect(() => { loadingRef.current = loading },  [loading])
  useEffect(() => { selectedRef.current = selected }, [selected])

  // RAF animation loop
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

  // Socket events
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
      if (prev === i) { targetRef.current = null; return null }
      const step       = (2 * Math.PI) / N
      const neutral    = -Math.PI / 2 + i * step
      let tgt          = -neutral
      while (tgt < rotRef.current) tgt += 2 * Math.PI
      targetRef.current = tgt
      return i
    })
  }

  const moved     = selected !== null
  const selField  = selected !== null ? FIELDS[selected] : null
  const layerData = selField
    ? (packet ? packet[selField.key] : null) ?? DEMO_DATA[selField.key] ?? null
    : null

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
          <circle cx={CX} cy={CY} r={HOLR - 2} fill="transparent" className="centre-hit" onClick={startCapture} />
          <text x={CX} y={CY} textAnchor="middle" dominantBaseline="middle"
            fontSize={loading ? 14 : 17}
            className={`ctxt${loading ? ' ctxt-pulse' : ''}`}
            onClick={startCapture}>
            {loading ? '···' : 'CAPTURE'}
          </text>
        </svg>
      </div>

      {/* ── Info panel ── */}
      <div className={`panel${moved ? ' panel-on' : ''}`}>
        <button className="back-btn"
          onClick={() => { setSelected(null); selectedRef.current = null; targetRef.current = null }}>
          ← Back
        </button>

        {selField && (
          <>
            <div className="panel-title">{selField.label}</div>

            {/* Aggregation badge */}
            {packet?._meta && (
              <div className="agg-badge">
                {packet._meta.totalFramesCaptured} packets · {packet._meta.captureTarget}
              </div>
            )}

            <div className="panel-kv-wrap">
              <LayerPanel fieldKey={selField.key} data={layerData} />
            </div>
          </>
        )}

        <div className="panel-status">{status}</div>
      </div>
    </div>
  )
}