
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = await db.collection('users').find({
            $or: [
                { avatarUrl: { $exists: true, $ne: null } },
                { videoUrl: { $exists: true, $ne: null } }
            ]
        }).project({ firstName: 1, videoUrl: 1, onboardingStatus: 1 }).limit(20).toArray();

        const output = {
            total: users.length,
            users: users.map(u => ({
                name: u.firstName,
                status: u.onboardingStatus,
                video: u.videoUrl
            }))
        };
        require('fs').writeFileSync('media_audit.json', JSON.stringify(output, null, 2));
        console.log('Audit saved to media_audit.json');

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
run();
