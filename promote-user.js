const mongoose = require('mongoose');
const User = require('./models/User');
require('dotenv').config();

const emailToPromote = process.argv[2];

if (!emailToPromote) {
    console.log('Usage: node promote-user.js <email>');
    process.exit(1);
}

mongoose.connect(process.env.MONGODB_URI)
    .then(async () => {
        const user = await User.findOne({ email: emailToPromote.toLowerCase() });
        if (!user) {
            console.error('User not found');
            process.exit(1);
        }

        user.role = 'admin';
        await user.save();
        console.log(`✅ User ${emailToPromote} has been promoted to admin.`);
        process.exit(0);
    })
    .catch(err => {
        console.error('Error:', err);
        process.exit(1);
    });
