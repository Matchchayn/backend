
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');

        const victoria = await users.findOne({ email: 'victoriialinda998@gmail.com' });

        console.log('\n--- VICTORIA LIKES (USERS WHO LIKED HER) ---');
        const likes = await users.find({
            likedUsers: victoria._id,
        }).project({ firstName: 1, likedUsers: 1 }).toArray();

        console.log(`Total users who liked Victoria: ${likes.length}`);
        let pendingLikes = 0;

        const myLiked = (victoria.likedUsers || []).map(id => id.toString());
        const myRejected = (victoria.rejectedUsers || []).map(id => id.toString());
        const myMatches = (victoria.matches || []).map(id => id.toString());

        likes.forEach(u => {
            const uid = u._id.toString();
            const likedBack = myLiked.includes(uid);
            const rejected = myRejected.includes(uid);
            const isMatch = myMatches.includes(uid);
            console.log(` - ${u.firstName} (${uid}) : likedBack=${likedBack}, rejected=${rejected}, isMatch=${isMatch}`);
            if (!likedBack && !rejected) pendingLikes++;
        });

        console.log(`\nPending Likes (should show on frontend): ${pendingLikes}`);

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
run();
