
const http = require('http');

http.get({'host': 'api.ipify.org', 'port': 80, 'path': '/'}, function(resp) {
  resp.on('data', function(ip) {
    console.log("Your Public IP: " + ip);
  });
}).on('error', function(e) {
  console.log("Error getting IP: " + e.message);
});
