
require('dotenv').config();
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    firstName: String,
    videoUrl: String,
    avatarUrl: String,
    onboardingStatus: String
}, { strict: false });

const User = mongoose.model('UserAudit', userSchema, 'users');

async function run() {
    try {
        await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
        console.log('Connected');
        const users = await User.find({}).lean();
        console.log(`Total users found: ${users.length}`);
        users.forEach(u => {
            console.log(`[${u.onboardingStatus || 'no-status'}] ${u.firstName || 'NoName'}: vURL=${u.videoUrl ? 'YES' : 'NONE'}, aURL=${u.avatarUrl ? 'YES' : 'NONE'}`);
            if (u.videoUrl) console.log(`  -> ${u.videoUrl.substring(0, 60)}...`);
        });
    } catch (err) {
        console.error('Error:', err.message);
    } finally {
        await mongoose.disconnect();
    }
}
run();
