const mongoose = require('mongoose');
const User = require('./models/User');
const Status = require('./models/Status');
if (require('fs').existsSync('.env')) {
    require('dotenv').config();
}

async function check() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const statuses = await Status.find().limit(5).populate('user');
        console.log('LATEST_STATUS_DATA_START');
        statuses.forEach((s, i) => {
            console.log(`STATUS_${i}: ${s.imageUrl}`);
        });
        console.log('LATEST_STATUS_DATA_END');
        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}
check();
