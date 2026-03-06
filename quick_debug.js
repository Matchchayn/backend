
require('dotenv').config();
const { MongoClient } = require('mongodb');

async function debug() {
    console.log("Starting quick debug...");
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = await db.collection('users').find({}).limit(10).toArray();
        console.log("Users sampled:", users.length);
        users.forEach(u => {
            console.log(`Email: ${u.email} | ID: ${u._id}`);
            console.log(`Liked count: ${u.likedUsers ? u.likedUsers.length : 0}`);
        });
        
        const victoria = await db.collection('users').findOne({ email: 'victoriialinda998@gmail.com' });
        if (victoria) {
             console.log("\nVictoria found. ID Type:", typeof victoria._id);
             console.log("Likes raw:", victoria.likedUsers);
        }

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
debug();
