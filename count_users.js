
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

async function countUsers() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to DB');
        const count = await User.countDocuments();
        console.log('Total Users:', count);
        const completedCount = await User.countDocuments({ onboardingStatus: 'completed' });
        console.log('Completed Users:', completedCount);
    } catch (err) {
        console.error(err);
    } finally {
        await mongoose.disconnect();
    }
}
countUsers();
