
require('dotenv').config();
const { MongoClient } = require('mongodb');

async function debug() {
    console.log("Starting debug...");
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        console.log("Connected to DB.");
        const db = client.db('Matchchayn');
        const user = await db.collection('users').findOne({ email: 'victoriialinda998@gmail.com' });
        
        if (!user) {
            console.log("Victoria not found in Matchchayn. Searching all users...");
            const all = await db.collection('users').find({}).limit(5).toArray();
            console.log("Sample users:", all.map(u => u.email));
            return;
        }

        console.log("Victoria ID:", user._id);
        console.log("Liked Users Raw:", user.likedUsers);
        
        if (user.likedUsers && user.likedUsers.length > 0) {
            const profiles = await db.collection('users').find({ _id: { $in: user.likedUsers } }).toArray();
            console.log("Profiles found in DB:", profiles.length);
            profiles.forEach(p => console.log(`- ${p.firstName} (${p.email})`));
        }

    } catch (err) {
        console.error("Error:", err);
    } finally {
        await client.close();
        console.log("Done.");
    }
}

debug();
