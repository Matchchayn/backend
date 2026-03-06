
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');

        const usersWithTypo = await users.find({ videoUrl: /446\.r2\.dev/ }).project({ firstName: 1, videoUrl: 1 }).toArray();
        console.log('Users with typo in videoUrl:', JSON.stringify(usersWithTypo, null, 2));

        if (usersWithTypo.length > 0) {
            console.log('Fixing typo...');
            for (const user of usersWithTypo) {
                const fixedUrl = user.videoUrl.replace('446.r2.dev', '46.r2.dev');
                await users.updateOne({ _id: user._id }, { $set: { videoUrl: fixedUrl } });
                console.log(`Updated ${user.firstName}'s videoUrl`);
            }
        } else {
            console.log('No users with 446 typo found.');
        }

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
run();
