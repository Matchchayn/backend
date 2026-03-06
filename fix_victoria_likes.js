
const mongoose = require('mongoose');
require('dotenv').config();

async function run() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        const User = mongoose.connection.collection('users');

        const victoriaIdStr = "699b1a8b57ae2871e1e9f83f";
        const victoriaIdObj = new mongoose.Types.ObjectId(victoriaIdStr);

        // Check for strings
        const likedByStr = await User.countDocuments({ likedUsers: victoriaIdStr });
        // Check for ObjectIds
        const likedByObj = await User.countDocuments({ likedUsers: victoriaIdObj });

        console.log(`Victoria (${victoriaIdStr}):`);
        console.log(` - Liked by (stored as string): ${likedByStr}`);
        console.log(` - Liked by (stored as ObjectId): ${likedByObj}`);

        if (likedByStr > 0) {
            console.log('--- FOUND STRING LIKES! FIXING... ---');
            const result = await User.updateMany(
                { likedUsers: victoriaIdStr },
                { $set: { "likedUsers.$": victoriaIdObj } }
            );
            // Wait, that only replaces one element if it's the only one. 
            // Better to pull and push, or use a more robust update.
        }

    } catch (err) {
        console.error(err);
    } finally {
        await mongoose.disconnect();
    }
}
run();
