from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/create-object")
def create_object():
    packet = {
    "layer1": {
        "interface": "eth0",
        "interfaceIndex": 2,
        "linkSpeed": "1Gbps",
        "duplexMode": "full",
        "direction": "ingress",
        "timestamp": "10:23:41.12341"
    },

    "layer2": {
        "packetNum": 134,
        "packetLength": "74 bytes",
        "srcMAC": "00:1A:2B:3C:4D:5E",
        "dstMAC": "10:22:33:44:55:66",
        "etherType": "Ethernet II",
        "frameType": "unicast",
        "vlanID": 100,
        "vlanPriority": 3,
        "dei": 0
    },

    "layer3": {
        "ipVersion": 4,
        "srcIP": "192.168.1.10",
        "dstIP": "142.250.190.78",
        "TTL": 64,
        "protocol": "TCP",
        "headerLength": 20,
        "totalLength": 74,
        "identification": 54321,
        "fragmentOffset": 0,
        "df": True,
        "mf": False,
        "checksum": "0x8c21",
        "dscp": 0,
        "ecn": 0
    },

    "layer4": {
        "srcPort": 54321,
        "dstPort": 443,
        "protocol": "TCP",
        "seq": 1001,
        "ack": 2001,
        "flags": "syn",
        "windowSize": 64240,
        "tcpHeaderLength": 32,
        "checksum": "0x4fa2",
        "urgentPointer": 0,
        "mss": 1460,
        "windowScale": 7,
        "sackPermitted": True
    },

    "sessionPresentation": {
        "flowID": "192.168.1.10:54321-142.250.190.78:443",
        "sessionState": "SYN_SENT",
        "packetsInFlow": 5,
        "bytesInFlow": 740,
        "flowDuration": "0.3s",
        "tlsVersion": "TLS1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "compression": "none",
        "certificateIssuer": "Google Trust Services",
        "certificateSubject": "google.com"
    },

    "layer7": {
        "applicationProtocol": "HTTP",
        "httpMethod": "GET",
        "httpHost": "google.com",
        "httpPath": "/search",
        "statusCode": 200,
        "userAgent": "Mozilla/5.0",
        "contentType": "text/html"
    },

    "kernelMetadata": {
        "pid": 4321,
        "processName": "curl",
        "uid": 1000,
        "cgroupID": "docker-abc123",
        "containerID": "container_78fa12",
        "networkNamespace": 4026531993
    },

    "payload": {
        "payloadLength": 8,
        "hexDump": "48 54 54 50 2F 31 2E 31"
    }
}

    return jsonify(packet)

if __name__ == "__main__":
    app.run(debug=True)
