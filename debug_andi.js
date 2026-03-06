
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

async function checkAndi() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to DB');

        const andi = await User.findOne({ firstName: 'Andi' });
        if (andi) {
            console.log('Found Andi:');
            console.log('videoUrl:', andi.videoUrl ? andi.videoUrl.substring(0, 100) : 'MISSING');
            console.log('hasVideoProperty:', andi.toObject().hasOwnProperty('videoUrl'));
            console.log('avatarUrl starts with:', andi.avatarUrl ? andi.avatarUrl.substring(0, 50) : 'MISSING');
            console.log('onboardingStatus:', andi.onboardingStatus);
        } else {
            console.log('Andi not found');
        }

    } catch (err) {
        console.error(err);
    } finally {
        await mongoose.disconnect();
    }
}

checkAndi();
