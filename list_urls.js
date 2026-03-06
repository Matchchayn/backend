
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

async function listUserUrls() {
    try {
        mongoose.set('bufferCommands', true);
        await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 15000,
        });
        console.log('Connected to DB');

        console.log('Querying for all users with media...');
        const users = await User.find({
            $or: [
                { avatarUrl: { $exists: true, $ne: null } },
                { videoUrl: { $exists: true, $ne: null } }
            ]
        })
            .select('firstName avatarUrl videoUrl onboardingStatus')
            .lean();
        console.log('Query complete');

        console.log(`Found ${users.length} completed profiles:\n`);

        users.forEach(u => {
            console.log(`User: ${u.firstName}`);
            console.log(` - Avatar: ${u.avatarUrl ? u.avatarUrl.substring(0, 80) + '...' : 'NONE'}`);
            console.log(` - Video:  ${u.videoUrl ? u.videoUrl.substring(0, 80) + '...' : 'NONE'}`);
            console.log('-----------------------------------');
        });

    } catch (err) {
        console.error(err);
    } finally {
        await mongoose.disconnect();
    }
}

listUserUrls();
