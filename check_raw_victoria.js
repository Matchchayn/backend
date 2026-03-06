
require('dotenv').config();
const { MongoClient, ObjectId } = require('mongodb');

async function checkRawVictoria() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const victoria = await db.collection('users').findOne({ email: 'victoriialinda998@gmail.com' });
        
        console.log("Victoria's likedUsers raw:");
        console.log(victoria.likedUsers);
        
        if (victoria.likedUsers && victoria.likedUsers.length > 0) {
            const profiles = await db.collection('users').find({
                _id: { $in: victoria.likedUsers }
            }).project({ firstName: 1, avatarUrl: 1 }).toArray();
            
            console.log("Found profile details count:", profiles.length);
            profiles.forEach(p => console.log(`- ${p.firstName}, Avatar: ${p.avatarUrl ? 'YES' : 'NO'}`));
        }
        
    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}

checkRawVictoria();
