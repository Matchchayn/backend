
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');

        const victoria = await users.findOne({ email: 'victoriialinda998@gmail.com' });

        const myLiked = (victoria.likedUsers || []).map(id => id.toString());
        const myRejected = (victoria.rejectedUsers || []).map(id => id.toString());
        const myMatches = (victoria.matches || []).map(id => id.toString());

        const likes = await users.find({ likedUsers: victoria._id }).project({ firstName: 1 }).toArray();
        let pendingLikes = 0;

        likes.forEach(u => {
            const uid = u._id.toString();
            const likedBack = myLiked.includes(uid);
            const rejected = myRejected.includes(uid);
            if (!likedBack && !rejected) pendingLikes++;
        });

        console.log(`Victoria liked: ${myLiked.length} users`);
        console.log(`Victoria has: ${myMatches.length} matches`);
        console.log(`Pending Likes: ${pendingLikes} users`);
        console.log(`Total users in DB: ${await users.countDocuments()}`);

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
        process.exit(0);
    }
}
run();
