const dgram = require('dgram');
const fs = require('fs');

const LISTEN_PORT = 50102; // Port to receive on
const FORWARD_PORT = 6678; // Port the GUI listens on
const FORWARD_ADDR = '236.6.7.8'; // Multicast group for GUI
const DEBUG = true; // Toggle CSV logging

const listenSocket = dgram.createSocket('udp4');
const forwardSocket = dgram.createSocket('udp4');

// Setup CSV logging if DEBUG is enabled
let csvStream = null;
if (DEBUG) {
  const filename = `simrad_packets_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
  csvStream = fs.createWriteStream(filename, { flags: 'a' });
  csvStream.write('timestamp,length,data(hex)\n');
  console.log(`CSV logging enabled: ${filename}`);
}

listenSocket.on('listening', () => {
  const address = listenSocket.address();
  console.log(`Listening for Simrad packets on ${address.address}:${address.port}`);
});

listenSocket.on('message', (msg, rinfo) => {
  const hexData = msg.toString('hex');
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${rinfo.address}:${rinfo.port} | ${msg.length} bytes`);

  if (DEBUG && csvStream) {
    csvStream.write(`${timestamp},${msg.length},${hexData}\n`);
  }

  // forward packet to multicast group so GUI can receive it
  forwardSocket.send(msg, 0, msg.length, FORWARD_PORT, FORWARD_ADDR, (err) => {
    if (err) {
      console.error('Forward error:', err);
    }
  });
});

listenSocket.bind(LISTEN_PORT);
