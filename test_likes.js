
const fs = require('fs');
const token = fs.readFileSync('current_token.txt', 'utf8').trim();

async function fetchFromApi(path) {
    console.log(`Sending GET request to ${path}`);
    const res = await fetch(`http://127.0.0.1:5000${path}`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    console.log(`Got response for ${path}: ${res.status}`);
    const text = await res.text();
    console.log(`Got response body for ${path}`);
    if (!res.ok) {
        console.log(`${path} failed: ${res.status} => ${text}`);
        return null;
    }
    return JSON.parse(text);
}

async function run() {
    try {
        console.log("Fetching /api/user/likes...");
        const likes = await fetchFromApi('/api/user/likes');
        if (likes) {
            console.log(`Likes count: ${likes.length}`);
            if (likes.length > 0) console.log(JSON.stringify(likes[0], null, 2));
        }
    } catch (err) {
        console.error(err);
    }
}
run();
