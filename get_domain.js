const mongoose = require('mongoose');
const Status = require('./models/Status');
require('dotenv').config();

async function check() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const s = await Status.findOne({ imageUrl: /^https/ });
        if (s) {
            console.log('DOMAIN:' + s.imageUrl.split('/uploads')[0]);
        } else {
            console.log('No valid URL found');
        }
        process.exit(0);
    } catch (err) {
        process.exit(1);
    }
}
check();
