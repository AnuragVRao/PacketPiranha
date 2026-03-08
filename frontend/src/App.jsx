import { useState } from 'react'
import './App.css'

function App() {
  const [packet, setPacket] = useState({});

  async function getPacket(){
    const res = await fetch("http://localhost:5000/create-object");
    const data = await res.json();
    setPacket(data);
    console.log(packet);
  }

  return (
    <>
      <button onClick={getPacket}></button>
    </>
  )
}

export default App
