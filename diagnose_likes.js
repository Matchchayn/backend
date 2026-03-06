
const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');

        const myIdStr = "699b1a8b57ae2871e1e9f83f";
        const myId = new ObjectId(myIdStr);

        const me = await users.findOne({ _id: myId });
        console.log(`Victoria found: ${!!me}`);

        const myLiked = (me.likedUsers || []).map(id => id.toString());
        const myRejected = (me.rejectedUsers || []).map(id => id.toString());

        console.log(`My Liked count: ${myLiked.length}, My Rejected count: ${myRejected.length}`);

        // This simulates the query in /api/user/likes
        // likes = await User.find({ likedUsers: req.user.id, _id: { $nin: [...me.likedUsers, ...me.rejectedUsers] } })

        // Since we are using MongoClient, we need to match how mongoose would cast ObjectId
        // If the DB has ObjectIds in arrays, we need to query with ObjectIds
        const excludeIds = [...(me.likedUsers || []), ...(me.rejectedUsers || [])];

        console.log(`Exclude IDs total: ${excludeIds.length}`);

        const likesQuery = {
            likedUsers: myIdStr, // Or myId depending on how it's stored
        };

        // Check how it's stored in other users
        const someoneWhoLikedMe = await users.findOne({ likedUsers: myIdStr });
        const someoneWhoLikedMeObj = await users.findOne({ likedUsers: myId });

        console.log(`Stored as string: ${!!someoneWhoLikedMe}, Stored as ObjectId: ${!!someoneWhoLikedMeObj}`);

        const likes = await users.find({
            likedUsers: { $in: [myIdStr, myId] },
            _id: { $nin: excludeIds }
        }).toArray();

        console.log(`FOUND LIKES: ${likes.length}`);
        likes.forEach(l => console.log(` - ${l.firstName}`));

        // Wait, why would Victoria's front-end show 0 likes?
        // Let's check the API response directly again.

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
        process.exit(0);
    }
}
run();
