const mongoose = require('mongoose');
const User = require('./models/User');
const Status = require('./models/Status');
require('dotenv').config();

const WRONG_DOMAIN = 'de446cdd';
const CORRECT_DOMAIN = 'de46cdd';

async function repair() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to MongoDB');

        // Fix Users
        const users = await User.find({
            $or: [
                { avatarUrl: new RegExp(WRONG_DOMAIN) },
                { secondaryPhotoUrl: new RegExp(WRONG_DOMAIN) },
                { thirdPhotoUrl: new RegExp(WRONG_DOMAIN) },
                { videoUrl: new RegExp(WRONG_DOMAIN) }
            ]
        });

        console.log(`Fixing ${users.length} users...`);
        for (let u of users) {
            if (u.avatarUrl) u.avatarUrl = u.avatarUrl.replace(WRONG_DOMAIN, CORRECT_DOMAIN);
            if (u.secondaryPhotoUrl) u.secondaryPhotoUrl = u.secondaryPhotoUrl.replace(WRONG_DOMAIN, CORRECT_DOMAIN);
            if (u.thirdPhotoUrl) u.thirdPhotoUrl = u.thirdPhotoUrl.replace(WRONG_DOMAIN, CORRECT_DOMAIN);
            if (u.videoUrl) u.videoUrl = u.videoUrl.replace(WRONG_DOMAIN, CORRECT_DOMAIN);
            await u.save();
            console.log(`  Fixed media for ${u.firstName}`);
        }

        // Fix Statuses
        const statuses = await Status.find({
            imageUrl: new RegExp(WRONG_DOMAIN)
        });

        console.log(`Fixing ${statuses.length} statuses...`);
        for (let s of statuses) {
            s.imageUrl = s.imageUrl.replace(WRONG_DOMAIN, CORRECT_DOMAIN);
            await s.save();
        }

        console.log('✅ Global repair finished!');
        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}

repair();
