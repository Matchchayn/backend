
const mongoose = require('mongoose');
require('dotenv').config();

const userSchema = new mongoose.Schema({}, { strict: false });
const User = mongoose.model('UserAudit', userSchema, 'users');

async function run() {
    try {
        await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
        console.log('Connected to MongoDB');

        const victoriaId = '699b1a8b57ae2871e1e9f83f';
        const me = await User.findById(victoriaId).lean();
        const matchIds = me.matches || [];
        console.log('Match IDs:', matchIds);

        console.log('Running find with $in...');
        const matches = await User.find({ _id: { $in: matchIds } }).lean();
        console.log(`Found ${matches.length} matches via $in.`);

    } catch (err) {
        console.error(err);
    } finally {
        await mongoose.disconnect();
    }
}
run();
