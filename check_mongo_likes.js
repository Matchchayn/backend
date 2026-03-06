
require('dotenv').config();
const mongoose = require('mongoose');

// Define a minimal User schema for the query
const userSchema = new mongoose.Schema({
    email: String,
    firstName: String,
    likedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    matches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const User = mongoose.models.User || mongoose.model('User', userSchema);

async function checkLikes() {
    try {
        console.log('Connecting to MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected.');

        const email = 'victoriialinda998@gmail.com';
        const user = await User.findOne({ email }).lean();

        if (!user) {
            console.log(`User ${email} not found.`);
            return;
        }

        console.log('\n--- User Info ---');
        console.log(`ID: ${user._id}`);
        console.log(`Email: ${user.email}`);
        console.log(`Name: ${user.firstName}`);
        
        console.log('\n--- Profiles THIS user Liked (Sent) ---');
        console.log(`Count: ${user.likedUsers?.length || 0}`);
        if (user.likedUsers?.length > 0) {
            const likedProfiles = await User.find({ _id: { $in: user.likedUsers } }).select('email firstName avatarUrl').lean();
            likedProfiles.forEach(p => console.log(`  - ${p.firstName} (${p.email}) - Image: ${p.avatarUrl ? 'YES' : 'NO'}`));
        }

        console.log('\n--- Profiles that liked THIS user (Received) ---');
        const likedBy = await User.find({ likedUsers: user._id }).select('email firstName avatarUrl').lean();
        console.log(`Count: ${likedBy.length}`);
        likedBy.forEach(p => console.log(`  - ${p.firstName} (${p.email})`));

        console.log('\n--- Matches ---');
        console.log(`Count: ${user.matches?.length || 0}`);

        await mongoose.connection.close();
        console.log('\nDisconnected.');
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
}

checkLikes();
