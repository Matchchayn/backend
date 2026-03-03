const mongoose = require('mongoose');
const User = require('./models/User');
const Status = require('./models/Status');
require('dotenv').config();

async function check() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const userUrls = await User.find({ avatarUrl: /^https/ }).distinct('avatarUrl');
        const statusUrls = await Status.find({ imageUrl: /^https/ }).distinct('imageUrl');

        const domains = new Set();
        [...userUrls, ...statusUrls].forEach(url => {
            if (url.includes('/uploads/')) {
                domains.add(url.split('/uploads/')[0]);
            }
        });

        console.log('Found domains:');
        domains.forEach(d => console.log(d));
        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}
check();
