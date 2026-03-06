
require('dotenv').config();
const { MongoClient } = require('mongodb');

async function debugRaw() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const user = await db.collection('users').findOne({ email: 'victoriialinda998@gmail.com' });
        
        console.log("Victoria's User Object dump:");
        console.log("---------------------------");
        console.log("ID:", user?._id);
        console.log("likedUsers Type:", Array.isArray(user?.likedUsers) ? "Array" : typeof user?.likedUsers);
        console.log("likedUsers Raw Contents:", JSON.stringify(user?.likedUsers));
        
        if (user?.likedUsers?.length > 0) {
            const firstEntry = user.likedUsers[0];
            console.log("\nFirst Like Entry:", firstEntry, "Type:", typeof firstEntry);
            
            // Try different search methods
            const byFirst = await db.collection('users').findOne({ _id: firstEntry });
            console.log("Found by Exact Entry:", byFirst ? "YES (" + byFirst.firstName + ")" : "NO");
            
            try {
                const { ObjectId } = require('mongodb');
                const asObj = (typeof firstEntry === 'string') ? new ObjectId(firstEntry) : firstEntry;
                const byObj = await db.collection('users').findOne({ _id: asObj });
                console.log("Found by ObjectId Search:", byObj ? "YES (" + byObj.firstName + ")" : "NO");
            } catch (e) { console.log("ObjectId conversion error"); }
        }

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
debugRaw();
