
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');
        const messages = db.collection('messages');
        const conversations = db.collection('conversations'); // If it exists

        const victoria = await users.findOne({ email: 'victoriialinda998@gmail.com' });
        console.log('--- VICTORIA AUDIT ---');
        console.log(`ID: ${victoria._id}`);
        console.log(`likedUsers: ${victoria.likedUsers ? victoria.likedUsers.length : 0}`);
        console.log(`matches: ${victoria.matches ? victoria.matches.length : 0}`);

        // Find who liked Victoria
        const likedBy = await users.countDocuments({ likedUsers: victoria._id });
        console.log(`Liked by: ${likedBy} users`);

        // Check messages
        const msgSent = await messages.countDocuments({ sender: victoria._id });
        const msgReceived = await messages.countDocuments({ receiver: victoria._id });
        console.log(`Messages: Sent=${msgSent}, Received=${msgReceived}`);

        if (msgSent > 0 || msgReceived > 0) {
            const lastMsg = await messages.findOne({
                $or: [{ sender: victoria._id }, { receiver: victoria._id }]
            }, { sort: { createdAt: -1 } });
            console.log('Last Message:', JSON.stringify(lastMsg, null, 2));
        }

        // Check conversations if they exist
        const collections = await db.listCollections().toArray();
        if (collections.some(c => c.name === 'conversations')) {
            const convos = await db.collection('conversations').find({
                participants: victoria._id
            }).toArray();
            console.log(`Conversations: ${convos.length}`);
        } else {
            console.log('No conversations collection found (probably using messages aggregation)');
        }

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
run();
