
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY5OWIxYThiNTdhZTI4NzFlMWU5ZjgzZiIsImlhdCI6MTc0MTE5OTExOSwiZXhwIjoxNzQxODAzNTE5fQ.VuOLSsfRHvQxpVjVrd8eAb5roOLMJxINiSKZ8NL9C9V';

async function testMatches() {
    try {
        const response = await fetch('http://localhost:5000/api/user/matches-feed', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            console.error('Response NOT OK:', response.status, await response.text());
            return;
        }

        const data = await response.json();
        console.log('Matches Count:', data.length);
        if (data.length > 0) {
            data.forEach(u => {
                console.log(`User: ${u.firstName}, videoUrl: ${u.videoUrl ? u.videoUrl.substring(0, 50) : 'undefined'}`);
            });
        }
    } catch (err) {
        console.error(err);
    }
}

testMatches();
