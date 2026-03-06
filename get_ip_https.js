
const https = require('https');

https.get('https://api.ipify.org', (resp) => {
  let data = '';
  resp.on('data', (chunk) => { data += chunk; });
  resp.on('end', () => { console.log("Public IP: " + data); });
}).on('error', (err) => { console.log("Error: " + err.message); });
