
require('dotenv').config();
const { MongoClient } = require('mongodb');

async function debug() {
    console.log("Victoria raw IDs check...");
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const victoria = await db.collection('users').findOne({ email: 'victoriialinda998@gmail.com' });
        
        if (!victoria) {
             console.log("Victoria not found");
             return;
        }

        console.log("ID:", victoria._id);
        console.log("raw likedUsers:", victoria.likedUsers);
        
        if (victoria.likedUsers && victoria.likedUsers.length > 0) {
             console.log("\nAttempting to find ONE profile by ID...");
             const firstId = victoria.likedUsers[0];
             console.log("First ID:", firstId, "Type:", typeof firstId);
             
             // Try searching with exact type
             const found = await db.collection('users').findOne({ _id: firstId });
             console.log("Found by exact ID?", found ? "YES (" + found.firstName + ")" : "NO");
             
             // Try searching with ObjectId if it was a string
             if (typeof firstId === 'string') {
                 try {
                     const { ObjectId } = require('mongodb');
                     const foundObj = await db.collection('users').findOne({ _id: new ObjectId(firstId) });
                     console.log("Found by ObjectId wrapper?", foundObj ? "YES" : "NO");
                 } catch (e) {
                     console.log("Not a valid ObjectId string");
                 }
             }
        }

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
debug();
