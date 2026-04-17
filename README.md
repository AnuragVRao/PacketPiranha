# PacketPiranha

PacketPiranha is an elegant, real-time network packet analyzer dashboard. It breaks down network traffic across the OSI Model (Layers 1-7) to provide an incredibly detailed, visual understanding of incoming metadata ranging from hardware-level frames to inferred upper-layer HTTP applications. 

Unlike standard user-level application listeners, PacketPiranha employs cutting-edge **eBPF (Extended Berkeley Packet Filter)** technology to silently and efficiently sniff kernel-level traffic in your system via a dynamic React-based UI.

## Architecture

- **Backend (Python / eBPF):**
  Located in the `/local` directory, the backend strictly requires a Linux environment (such as WSL2 on Windows) to compile and install Linux kernel probes. It relies on the BCC (BPF Compiler Collection) ecosystem, emitting live packet insights down a websocket using Socket.IO.
- **Frontend (React / Vite):** 
  Located in the `/frontend` directory, the dashboard displays robust real-time charts using elements like Chart.js traversing the OSI Model through a gear interface.

## Key Features
- **TCP Layer Visualization**: Dedicated layers representing hardware Link, Network, Transport, and Application properties natively.
- **Deep Metrics**: Interactive readouts for metrics like Top Talkers, Payload Window Size Trending, TCP Flag Distributions, Inter-packet arrival gaps, TTL distributions, and Connection states. 
- **Process Tracing**: Automatically correlates packets back to the exact system process originating or receiving the hit!

---

## Setup & Installation Instructions

Since PacketPiranha merges modern Node.js frontend tooling with low-level Linux Kernel scripting, you must run the project using a combination of environments. If you are on Windows, you must have **WSL2** (Windows Subsystem for Linux) properly configured.

### 1. Start the eBPF Backend Engine (in WSL or Native Linux)

Open a **WSL shell (e.g., Ubuntu)** inside your console:
```bash
# Navigate to the backend local directory
cd local

# Execute the start script (will request sudo automatically)
bash start.sh
```
> **What this does:** The script will automatically install missing networking dependencies (like `python3-bpfcc` and SocketIO adapters), skip incompatible kernel headers, run a fast `preflight.py` check, and mount the server onto `http://localhost:4242`.

### 2. Start the React Frontend Dashboard (in Windows / Primary Host)

Open a normal Command Prompt or PowerShell shell:
```bash
# Navigate to the frontend directory
cd frontend

# Install Node modules if you haven't already
npm install

# Start the Vite development server
npm run dev
```

### 3. Analyze Traffic
- Open your browser to your local UI host (usually `http://localhost:5173`).
- In the center of the mechanical gear layout, hit **Capture**. 
- Sit back, trigger some web requests or system loads natively, and click the gears representing `Layer 3`, `Layer 4`, or `Kernel` to see dynamic chart plotting reflect the current real-world state of your network.
