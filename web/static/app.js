(() => {
  const piLogEl = document.getElementById('pi-log');
  const espLogEl = document.getElementById('esp-log');
  const socket = io();

  function logToPi(msg) {
    const time = new Date().toLocaleTimeString();
    piLogEl.textContent += `[${time}] ${msg}\n`;
    piLogEl.scrollTop = piLogEl.scrollHeight;
  }

  function logToEsp(msg) {
    const time = new Date().toLocaleTimeString();
    espLogEl.textContent += `[${time}] ${msg}\n`;
    espLogEl.scrollTop = espLogEl.scrollHeight;
  }

  function routeLog(message) {
    // Route messages to appropriate log based on content
    if (message.includes('ESP32') || message.includes('Decrypted:') || message.includes('WiFi connected') || 
        message.includes('TCP connected') || message.includes('Decrypt verify failed') || 
        message.includes('started and connected')) {
      logToEsp(message);
    } else {
      logToPi(message);
    }
  }

  socket.on('connect', () => logToPi('Web client connected.'));
  socket.on('log', (data) => routeLog(data.message));

  document.getElementById('btn-configure').addEventListener('click', async () => {
    const passphrase = document.getElementById('passphrase').value.trim();
    if (!passphrase) { logToPi('Enter passphrase first.'); return; }
    try {
      const res = await fetch('/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase })
      });
      const j = await res.json();
      if (!j.ok) throw new Error(j.error || 'Failed');
      logToPi('Passphrase configured.');
    } catch (e) {
      logToPi(`Configure failed: ${e.message}`);
    }
  });

  document.getElementById('btn-send').addEventListener('click', async () => {
    const message = document.getElementById('message').value;
    if (!message) { logToPi('Enter a message.'); return; }
    try {
      const res = await fetch('/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message })
      });
      const j = await res.json();
      if (!j.ok) throw new Error(j.error || 'Failed');
    } catch (e) {
      logToPi(`Send failed: ${e.message}`);
    }
  });
})();






