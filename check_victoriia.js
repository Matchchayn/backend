const mongoose = require('mongoose');
require('dotenv').config();

const User = require('./models/User');

async function check() {
    await mongoose.connect(process.env.MONGODB_URI);
    const user = await User.findOne({ email: 'victoriialinda998@gmail.com' });
    if (!user) {
        console.log('User not found');
        return;
    }
    console.log('User ID:', user._id);
    console.log('Onboarding Status:', user.onboardingStatus);
    console.log('Matches type:', Array.isArray(user.matches) ? 'Array' : typeof user.matches);
    console.log('Matches count:', user.matches.length);
    if (user.matches.length > 0) {
        console.log('First match type:', typeof user.matches[0]);
        console.log('First match value:', user.matches[0]);
    }

    const matchesData = await User.find({ _id: { $in: user.matches } }).select('firstName email');
    console.log('Found matches in DB:', matchesData.length);
    matchesData.forEach(m => console.log(`- ${m.firstName} (${m.email})`));

    process.exit(0);
}

check();
