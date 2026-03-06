
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db(); // Uses db from URI
        const users = await db.collection('users').find({
            avatarUrl: { $exists: true },
        }).project({ firstName: 1, avatarUrl: 1, videoUrl: 1, onboardingStatus: 1 }).toArray();

        console.log(`Found ${users.length} users with photos:`);
        users.forEach(u => {
            console.log(`- ${u.firstName} (${u.onboardingStatus}):`);
            console.log(`  Photo: ${u.avatarUrl ? u.avatarUrl.substring(0, 50) : 'NONE'}`);
            console.log(`  Video: ${u.videoUrl ? u.videoUrl.substring(0, 50) : 'NONE'}`);
        });
    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
run();
