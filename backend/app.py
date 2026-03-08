from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/create-object")
def create_object():
    packet = {
        "packetNum" : 134,
        "timeStamp" : "10:23:41.12341",
        "packetLength" : "74 bytes",
        "interface" : "eth0",
        "srcMAC" : "00:1A:2B:3C:4D:5E",
        "dstMAC" : "10:22:33:44:55:66",
        "etherType" : "Ethernet II",
        "srcIP" : "192.168.1.10",
        "dstIP" : "142.250.190.78",
        "TTL" : "64",
        "protocol" : "TCP",
        "srcPort": 54321,
        "dstPort": 443,
        "flags": "syn",
        "seq": 1001,
        "hexDump" : "48 54 54 50 2F 31 2E 31"
    }

    return jsonify(packet)

if __name__ == "__main__":
    app.run(debug=True)
