
require('dotenv').config();
const { MongoClient } = require('mongodb');

async function listUrlsRaw() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        console.log('Connected to DB Raw');
        const db = client.db('Matchchayn');
        const users = await db.collection('users').find({}).limit(5).toArray();

        console.log(`Found ${users.length} completed profiles:\n`);
        users.forEach(u => {
            console.log(`User: ${u.firstName}`);
            console.log(` - Avatar: ${u.avatarUrl ? u.avatarUrl.substring(0, 80) + '...' : 'NONE'}`);
            console.log(` - Video:  ${u.videoUrl ? (u.videoUrl.startsWith('https') ? u.videoUrl : u.videoUrl.substring(0, 80) + '...') : 'NONE'}`);
            console.log('-----------------------------------');
        });
    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
listUrlsRaw();
