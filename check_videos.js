const mongoose = require('mongoose');
const User = require('./models/User');
require('dotenv').config();

async function check() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const users = await User.find({ videoUrl: { $exists: true, $ne: '' } });
        const fs = require('fs');
        let output = 'Users with videos:\n';
        users.forEach(u => {
            output += `User: ${u.firstName}, videoUrl: ${u.videoUrl}\n`;
        });
        fs.writeFileSync('video_urls.txt', output);
        process.exit(0);
    } catch (err) {
        process.exit(1);
    }
}
check();
