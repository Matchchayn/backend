const mongoose = require('mongoose');
const User = require('./models/User');
const Status = require('./models/Status');
require('dotenv').config();

async function check() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const users = await User.find({ avatarUrl: /de46cdd/ });
        console.log(`Users with de46cdd domain: ${users.length}`);
        users.forEach(u => console.log(u.firstName));

        const statuses = await Status.find({ imageUrl: /de46cdd/ });
        console.log(`Statuses with de46cdd domain: ${statuses.length}`);

        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}
check();
