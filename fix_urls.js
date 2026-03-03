const mongoose = require('mongoose');
const Status = require('./models/Status');
const User = require('./models/User');
require('dotenv').config();

const DOMAIN = 'https://pub-4fbb4303221540d9822de446cdd4b039d.r2.dev';

async function fix() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);

        // Fix Status collection
        const statuses = await Status.find({ imageUrl: /^undefined/ });
        console.log(`Found ${statuses.length} broken statuses`);
        for (let s of statuses) {
            s.imageUrl = s.imageUrl.replace('undefined', DOMAIN);
            await s.save();
        }

        // Also check User avatars/media just in case
        const users = await User.find({
            $or: [
                { avatarUrl: /^undefined/ },
                { secondaryPhotoUrl: /^undefined/ },
                { thirdPhotoUrl: /^undefined/ },
                { videoUrl: /^undefined/ }
            ]
        });
        console.log(`Found ${users.length} broken users`);
        for (let u of users) {
            if (u.avatarUrl?.startsWith('undefined')) u.avatarUrl = u.avatarUrl.replace('undefined', DOMAIN);
            if (u.secondaryPhotoUrl?.startsWith('undefined')) u.secondaryPhotoUrl = u.secondaryPhotoUrl.replace('undefined', DOMAIN);
            if (u.thirdPhotoUrl?.startsWith('undefined')) u.thirdPhotoUrl = u.thirdPhotoUrl.replace('undefined', DOMAIN);
            if (u.videoUrl?.startsWith('undefined')) u.videoUrl = u.videoUrl.replace('undefined', DOMAIN);
            await u.save();
        }

        console.log('✅ Repair complete');
        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}
fix();
