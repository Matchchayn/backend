
const mongoose = require('mongoose');
require('dotenv').config();

const userSchema = new mongoose.Schema({}, { strict: false });
const User = mongoose.model('UserAudit', userSchema, 'users');

async function run() {
    try {
        await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
        console.log('Connected to MongoDB');

        const victoria = await User.findOne({ email: 'victoriialinda998@gmail.com' }).lean();
        console.log('--- VICTORIA AUDIT ---');
        console.log(`ID: ${victoria._id}`);
        console.log(`likedUsers: ${victoria.likedUsers ? victoria.likedUsers.length : 0}`);
        console.log(`matches: ${victoria.matches ? victoria.matches.length : 0}`);
        console.log('Who did she like?');
        if (victoria.likedUsers) {
            for (const id of victoria.likedUsers) {
                const u = await User.findById(id).lean();
                console.log(` - ${u ? u.firstName : 'Unknown'} (${id})`);
            }
        }

        const likedBy = await User.find({ likedUsers: victoria._id }).lean();
        console.log(`\nLiked by: ${likedBy.length} users`);
        likedBy.forEach(u => console.log(` - ${u.firstName} (${u._id})`));

        // Let's get messages too
        const messageSchema = new mongoose.Schema({}, { strict: false });
        const Message = mongoose.model('MessageAudit', messageSchema, 'messages');
        const msgs = await Message.find({ $or: [{ sender: victoria._id }, { receiver: victoria._id }] }).lean();
        console.log(`\nMessages total: ${msgs.length}`);
        if (msgs.length > 0) {
            console.log('Sample Message:', msgs[msgs.length - 1].content);
        }

    } catch (err) {
        console.error(err);
    } finally {
        await mongoose.disconnect();
    }
}
run();
