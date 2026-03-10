import { useState } from 'react'
import { io } from 'socket.io-client'
import './App.css'

const socket = io('http://localhost:4242')

function App() {
  const [packet, setPacket] = useState(null)
  const [status, setStatus] = useState('Idle')
  const [loading, setLoading] = useState(false)

  socket.on('status', ({ message }) => {
    setStatus(message)
  })

  socket.on('packet_data', (data) => {
    setPacket(data)
    setLoading(false)
    setStatus('Capture complete')
    console.log('Packet received:', data)
  })

  socket.on('error', ({ message }) => {
    setStatus(`Error: ${message}`)
    setLoading(false)
  })

  function startCapture() {
    setLoading(true)
    setPacket(null)
    setStatus('Starting capture...')
    socket.emit('start_capture', { destIp: '1.1.1.1', dstPort: 80 })
  }

  return (
    <>
      <button onClick={startCapture} disabled={loading}>
        {loading ? 'Capturing...' : 'Run eBPF Capture'}
      </button>

      <p>Status: {status}</p>

      {packet && (
        <pre>{JSON.stringify(packet, null, 2)}</pre>
      )}
    </>
  )
}

export default App