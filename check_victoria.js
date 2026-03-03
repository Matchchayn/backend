const mongoose = require('mongoose');
const User = require('./models/User');
require('dotenv').config();

async function check() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const u = await User.findOne({ firstName: 'Victoria' });
        if (u) {
            console.log('Victoria Media:');
            console.log(`avatar: ${u.avatarUrl}`);
            console.log(`secondary: ${u.secondaryPhotoUrl}`);
            console.log(`video: ${u.videoUrl}`);
        }
        process.exit(0);
    } catch (err) {
        process.exit(1);
    }
}
check();
