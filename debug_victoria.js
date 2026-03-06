
require('dotenv').config();
const mongoose = require('mongoose');

async function debugVictoria() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const email = 'victoriialinda998@gmail.com';
        const user = await mongoose.connection.collection('users').findOne({ email: email });

        if (!user) {
            console.log("User not found.");
            return;
        }

        console.log("User ID:", user._id);
        console.log("Liked Users length:", user.likedUsers?.length || 0);
        console.log("Liked Users IDs:", JSON.stringify(user.likedUsers));
        
        // Find them
        if (user.likedUsers && user.likedUsers.length > 0) {
            const profiles = await mongoose.connection.collection('users')
                .find({ _id: { $in: user.likedUsers } })
                .project({ email: 1, firstName: 1, avatarUrl: 1 })
                .toArray();
            
            console.log("\n--- Found Profiles ---");
            profiles.forEach(p => {
                console.log(`- ${p.firstName} (${p.email}) ID: ${p._id} Image: ${p.avatarUrl ? 'YES' : 'NONE'}`);
            });
        }

        mongoose.connection.close();
    } catch (err) {
        console.error(err);
    }
}

debugVictoria();
