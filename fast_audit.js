
const fs = require('fs');
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');

        const victoria = await users.findOne({ email: 'victoriialinda998@gmail.com' });

        if (!victoria) {
            console.log('Victoria not found');
            return;
        }

        const myLiked = (victoria.likedUsers || []);
        console.log(`Victoria liked ${myLiked.length} users.`);

        const output = {
            likedUsers: [],
            likedByUsers: [],
            matches: []
        };

        // 1. People she liked
        if (myLiked.length > 0) {
            const likedProfiles = await users.find({ _id: { $in: myLiked } }).project({ firstName: 1, avatarUrl: 1, videoUrl: 1, likedUsers: 1 }).toArray();
            output.likedUsers = likedProfiles.map(u => ({
                _id: u._id,
                firstName: u.firstName,
                hasAvatar: !!u.avatarUrl,
                likedHerBack: (u.likedUsers || []).some(id => id.toString() === victoria._id.toString())
            }));
        }

        // 2. People who liked her
        const likedBy = await users.find({ likedUsers: victoria._id }).project({ firstName: 1, avatarUrl: 1 }).toArray();
        output.likedByUsers = likedBy.map(u => ({
            _id: u._id,
            firstName: u.firstName,
            hasAvatar: !!u.avatarUrl
        }));

        // 3. Matches
        if ((victoria.matches || []).length > 0) {
            const matches = await users.find({ _id: { $in: victoria.matches } }).project({ firstName: 1 }).toArray();
            output.matches = matches.map(m => m.firstName);
        }

        // Write to file to read safely
        fs.writeFileSync('likes_audit.json', JSON.stringify(output, null, 2));
        console.log('Successfully wrote to likes_audit.json');

    } catch (err) {
        console.error('Error:', err);
    } finally {
        await client.close();
    }
}

run();
