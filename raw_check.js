
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');

        // Find Andi specifically
        const andi = await users.findOne({ firstName: 'Andi' });
        require('fs').writeFileSync('andi_data.json', JSON.stringify(andi, null, 2));
        console.log('Andi data written to andi_data.json');

        // Find anyone with a video
        const hasVideo = await users.findOne({ videoUrl: { $exists: true, $ne: null } });
        console.log('\n--- ANYONE WITH VIDEO ---');
        if (hasVideo) {
            console.log(`User: ${hasVideo.firstName}`);
            console.log(`Video URL: ${hasVideo.videoUrl}`);
        } else {
            console.log('No one found with videoUrl');
        }

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
run();
