
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');

        const victoria = await users.findOne({ email: 'victoriialinda998@gmail.com' });
        console.log('--- VICTORIA DATA ---');
        console.log(`likedUsers: ${victoria.likedUsers ? victoria.likedUsers.length : 0}`);
        console.log(`rejectedUsers: ${victoria.rejectedUsers ? victoria.rejectedUsers.length : 0}`);
        console.log(`gender: ${victoria.gender}`);
        console.log(`id: ${victoria._id}`);

        // Find males that are not liked/rejected
        const excludedIds = [...(victoria.likedUsers || []), ...(victoria.rejectedUsers || []), victoria._id];
        const count = await users.countDocuments({
            _id: { $nin: excludedIds },
            gender: 'male',
            onboardingStatus: 'completed'
        });
        console.log(`Remaining pool of male matches: ${count}`);

        const sample = await users.find({
            _id: { $nin: excludedIds },
            gender: 'male',
            onboardingStatus: 'completed'
        }).limit(5).project({ firstName: 1, avatarUrl: 1 }).toArray();

        console.log('Sample potential targets:');
        sample.forEach(s => console.log(` - ${s.firstName} (hasPhoto: ${!!s.avatarUrl})`));

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
run();
