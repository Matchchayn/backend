
const { execSync } = require('child_process');

try {
    console.log("Searching for processes on port 5000...");
    const output = execSync('netstat -ano | findstr :5000').toString();
    const lines = output.trim().split('\n');
    const pids = new Set();
    
    lines.forEach(line => {
        const parts = line.trim().split(/\s+/);
        const pid = parts[parts.length - 1];
        if (pid && pid !== '0' && !isNaN(pid)) pids.add(pid);
    });

    if (pids.size > 0) {
        console.log(`Killing PIDs: ${Array.from(pids).join(', ')}`);
        pids.forEach(pid => {
            try {
                execSync(`taskkill /F /PID ${pid}`);
                console.log(`Killed ${pid}`);
            } catch (e) {
                console.log(`Failed to kill ${pid}: ${e.message}`);
            }
        });
    } else {
        console.log("No processes found on 5000.");
    }
} catch (e) {
    console.log("Port 5000 check failed (maybe it's empty).");
}
