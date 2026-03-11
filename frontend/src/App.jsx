import { useState, useEffect, useRef } from 'react'
import { io } from 'socket.io-client'
import './App.css'

const socket = io('http://localhost:4242')

// ── Packet fields represented as gear teeth ──────────────────────────────────
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

// ── Demo placeholder data — DEMO ONLY, replaced by real capture data ──────────
const DEMO_DATA = {
  layer1: {
    interface:      'eth0',
    interfaceIndex: 2,
    linkSpeed:      '1Gbps',
    duplexMode:     'full',
    direction:      'ingress',
    timestamp:      '10:23:41.12341',
  },
  layer2: {
    packetNum:    134,
    packetLength: '74 bytes',
    srcMAC:       '00:1A:2B:3C:4D:5E',
    dstMAC:       '10:22:33:44:55:66',
    etherType:    'Ethernet II',
    frameType:    'unicast',
    vlanID:       100,
    vlanPriority: 3,
    dei:          0,
  },
  layer3: {
    ipVersion:      4,
    srcIP:          '192.168.1.42',
    dstIP:          '1.1.1.1',
    TTL:            64,
    protocol:       'TCP',
    headerLength:   20,
    totalLength:    74,
    identification: 12345,
    fragmentOffset: 0,
    df:             true,
    mf:             false,
    checksum:       '0x0000',
    dscp:           0,
    ecn:            0,
  },
  layer4: {
    srcPort:         54321,
    dstPort:         443,
    protocol:        'TCP',
    seq:             1001,
    ack:             2001,
    flags:           'SYN',
    windowSize:      64240,
    tcpHeaderLength: 32,
    checksum:        '0x4fa2',
    urgentPointer:   0,
    mss:             1460,
    windowScale:     7,
    sackPermitted:   true,
  },
  sessionPresentation: {
    flowID:             '192.168.1.42:?-1.1.1.1:?',
    sessionState:       'SYN_SENT',
    packetsInFlow:      5,
    bytesInFlow:        740,
    flowDuration:       '0.3s',
    tlsVersion:         'TLS1.3',
    cipherSuite:        'TLS_AES_128_GCM_SHA256',
    compression:        'none',
    certificateIssuer:  'Google Trust Services',
    certificateSubject: 'google.com',
  },
  layer7: {
    applicationProtocol: 'HTTP',
    httpMethod:          'GET',
    httpHost:            'google.com',
    httpPath:            '/search',
    statusCode:          200,
    userAgent:           'Mozilla/5.0',
    contentType:         'text/html',
  },
  kernelMetadata: {
    pid:              4321,
    processName:      'curl',
    uid:              1000,
    cgroupID:         'docker-abc123',
    containerID:      'container_78fa12',
    networkNamespace: 4026531993,
  },
  payload: {
    payloadLength: 8,
    hexDump:       '48 54 54 50 2F 31 2E 31',
  },
}

// ── Gear geometry ─────────────────────────────────────────────────────────────
const N    = FIELDS.length
const CX   = 250, CY = 250
const OUTR = 148
const INNR = 110
const HOLR = 52
const LBLR = 186
const FRAC = 0.55

const SLOW_SPEED = 0.0018  // rad/frame  ≈ 6°/s at 60 fps
const LOAD_SPEED = 0.025   // rad/frame during capture

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

/** Annular sector covering the physical tooth face for tooth i */
function buildToothSector(i) {
  const step = (2 * Math.PI) / N
  const half = (FRAC * step) / 2
  const a1   = -Math.PI / 2 + i * step - half
  const a2   = a1 + FRAC * step
  const r1   = INNR - 6, r2 = OUTR + 10
  const [ox1, oy1] = pt(r2, a1)
  const [ox2, oy2] = pt(r2, a2)
  const [ix1, iy1] = pt(r1, a1)
  const [ix2, iy2] = pt(r1, a2)
  const f = ([x, y]) => `${x.toFixed(2)},${y.toFixed(2)}`
  return [
    `M${f([ix1, iy1])}`,
    `L${f([ox1, oy1])}`,
    `A${r2},${r2},0,0,1,${f([ox2, oy2])}`,
    `L${f([ix2, iy2])}`,
    `A${r1},${r1},0,0,0,${f([ix1, iy1])}`,
    'Z',
  ].join('')
}

const HIT_SECTORS = FIELDS.map((_, i) => buildToothSector(i))

// ── Component ─────────────────────────────────────────────────────────────────
export default function App() {
  const [packet,   setPacket]   = useState(null)
  const [status,   setStatus]   = useState('Click CAPTURE to begin')
  const [loading,  setLoading]  = useState(false)
  const [selected, setSelected] = useState(null)
  const [hovered,  setHovered]  = useState(null)

  // RAF-driven rotation (mutated directly — no re-renders)
  const gearGRef    = useRef(null)   // <g> wrapping the physical gear body + labels
  const labelRefs   = useRef([])     // refs to each label <text> for counter-rotation
  const rotRef      = useRef(0)      // current cumulative rotation (radians)
  const targetRef   = useRef(null)   // null = free/stopped; number = snap target
  const selectedRef = useRef(null)   // mirrors `selected` state — freeze when non-null
  const loadingRef  = useRef(false)
  const rafRef      = useRef(null)

  // keep loadingRef in sync with React state
  useEffect(() => { loadingRef.current = loading }, [loading])
  // keep selectedRef in sync so the RAF loop can read it without closures
  useEffect(() => { selectedRef.current = selected }, [selected])

  // continuous animation loop
  useEffect(() => {
    function animate() {
      if (targetRef.current !== null) {
        // easing toward snap target
        const diff = targetRef.current - rotRef.current
        if (Math.abs(diff) < 0.002) {
          rotRef.current = targetRef.current
          targetRef.current = null   // snap complete — gear parks here
        } else {
          rotRef.current += diff * 0.08
        }
      } else if (selectedRef.current === null) {
        // free spin only when nothing is selected
        rotRef.current += loadingRef.current ? LOAD_SPEED : SLOW_SPEED
      }
      // else: tooth is selected and snap is done → stay frozen
      const deg = (rotRef.current * 180) / Math.PI
      if (gearGRef.current) {
        gearGRef.current.setAttribute('transform', `rotate(${deg}, ${CX}, ${CY})`)
      }
      // counter-rotate each label so text stays upright while orbiting with tooth
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
    targetRef.current = null   // resume free spin
    setStatus('Starting capture…')
    socket.emit('start_capture', { destIp: '1.1.1.1', dstPort: 80 })
  }

  function pickTooth(i) {
    setSelected(prev => {
      if (prev === i) {
        // deselect → resume spinning
        targetRef.current = null
        return null
      }
      // snap tooth i to the east position (angle 0 = rightmost)
      const step        = (2 * Math.PI) / N
      const toothNeutral = -Math.PI / 2 + i * step
      // rotation R such that R + toothNeutral ≡ 0 (mod 2π) → R = -toothNeutral
      let tgt = -toothNeutral
      // always move clockwise (forward) to the next occurrence
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

          {/* Gear body + labels in same rotating group so labels orbit with teeth */}
          <g ref={gearGRef}>
            <path d={GEAR_PATH} className="gear-body" />
            <circle cx={CX} cy={CY} r={HOLR} className="gear-hole" />

            {/* Invisible tooth hit sectors — inside rotating group so they track teeth */}
            {HIT_SECTORS.map((d, i) => (
              <path
                key={`hit-${i}`}
                d={d}
                fill="transparent"
                stroke="none"
                style={{ cursor: 'pointer' }}
                onClick={() => pickTooth(i)}
                onMouseEnter={() => setHovered(i)}
                onMouseLeave={() => setHovered(null)}
              />
            ))}

            {FIELDS.map((f, i) => {
              const [lx, ly] = LABEL_POS[i]
              const active   = selected === i || hovered === i
              const spaceIdx = f.label.lastIndexOf(' ')
              const lines    = spaceIdx !== -1
                ? [f.label.slice(0, spaceIdx), f.label.slice(spaceIdx + 1)]
                : [f.label]
              return (
                <text
                  key={i}
                  ref={el => { labelRefs.current[i] = el }}
                  x={lx.toFixed(2)}
                  y={ly.toFixed(2)}
                  textAnchor="middle"
                  dominantBaseline="middle"
                  fontSize={active ? 12.5 : 11}
                  className={`lbl${active ? ' lbl-on' : ''}`}
                  style={{ cursor: 'pointer' }}
                  onClick={() => pickTooth(i)}
                  onMouseEnter={() => setHovered(i)}
                  onMouseLeave={() => setHovered(null)}
                >
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

          {/* Centre CAPTURE button */}
          <circle cx={CX} cy={CY} r={HOLR - 2} fill="transparent" className="centre-hit" onClick={startCapture} />
          <text
            x={CX} y={CY}
            textAnchor="middle"
            dominantBaseline="middle"
            fontSize={loading ? 14 : 17}
            className={`ctxt${loading ? ' ctxt-pulse' : ''}`}
            onClick={startCapture}
          >
            {loading ? '···' : 'CAPTURE'}
          </text>
        </svg>
      </div>

      {/* ── Info panel ── */}
      <div className={`panel${moved ? ' panel-on' : ''}`}>
        <button className="back-btn" onClick={() => { setSelected(null); selectedRef.current = null; targetRef.current = null }}>← Back</button>

        {selField && (
          <>
            <div className="panel-title">{selField.label}</div>
            <div className="panel-kv">
              {layerData
                ? Object.entries(layerData).map(([k, v]) => (
                    <div key={k} className="kv-row">
                      <span className="kv-key">{k}</span>
                      <span className="kv-val">{String(v)}</span>
                    </div>
                  ))
                : <span className="kv-empty">No data</span>
              }
            </div>
          </>
        )}

        <div className="panel-status">{status}</div>
      </div>

    </div>
  )
}