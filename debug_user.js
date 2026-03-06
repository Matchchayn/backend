
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

async function checkUser(userId) {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to DB');
        
        const user = await User.findById(userId).lean();
        if (!user) {
            console.log('User not found');
            return;
        }
        
        console.log('User:', user.email, user.firstName);
        console.log('Liked Users (Sent):', user.likedUsers?.length || 0);
        console.log('Matches:', user.matches?.length || 0);
        
        // Find users who liked this user
        const likedBy = await User.find({ likedUsers: userId }).select('email firstName').lean();
        console.log('Liked By (Received):', likedBy.length);
        likedBy.forEach(u => console.log(`  - ${u.firstName} (${u.email})`));
        
        mongoose.connection.close();
    } catch (err) {
        console.error(err);
    }
}

checkUser('699b1a8b57ae2871e1e9f83f');
