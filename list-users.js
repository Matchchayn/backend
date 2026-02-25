const mongoose = require('mongoose');
require('dotenv').config();
const User = require('./models/User');

async function listUsers() {
    try {
        console.log('Connecting to MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected successfully.\n');

        const users = await User.find({}, 'email firstName lastName username onboardingStatus createdAt');

        if (users.length === 0) {
            console.log('No users found in the database.');
        } else {
            console.log(`Found ${users.length} users:`);
            console.table(users.map(u => ({
                ID: u._id.toString(),
                Email: u.email,
                Name: `${u.firstName || ''} ${u.lastName || ''}`.trim() || 'N/A',
                Username: u.username || 'N/A',
                Status: u.onboardingStatus,
                Joined: u.createdAt ? u.createdAt.toLocaleDateString() : 'N/A'
            })));
        }

    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        await mongoose.disconnect();
        console.log('\nDisconnected from MongoDB.');
    }
}

listUsers();
