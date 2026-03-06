const mongoose = require('mongoose');

const uri = "mongodb+srv://josephakpansunday_db_user:Y7NIxaetH1p266HC@matchchayn.ibgx3ys.mongodb.net/Matchchayn?retryWrites=true&w=majority";

const userSchema = new mongoose.Schema({
    email: String,
    firstName: String,
    lastName: String,
    likedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    rejectedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    matches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
});

const User = mongoose.model('User', userSchema);

async function run() {
    try {
        await mongoose.connect(uri);
        const emails = ['victorialinda998@gmail.com', 'victoriialinda998@gmail.com'];
        let result = "";

        for (const email of emails) {
            result += `\n--- Searching for: ${email} ---\n`;
            const user = await User.findOne({ email }).populate('matches', 'email firstName lastName').populate('likedUsers', 'email firstName lastName');

            if (!user) {
                result += `User not found.\n`;
                continue;
            }

            result += `Name: ${user.firstName} ${user.lastName}\n`;
            result += `ID: ${user._id}\n`;
            result += `Liked Users (${user.likedUsers.length}):\n`;
            user.likedUsers.forEach(u => result += `  - ${u.email} (${u.firstName} ${u.lastName})\n`);

            result += `Matches (${user.matches.length}):\n`;
            user.matches.forEach(u => result += `  - ${u.email} (${u.firstName} ${u.lastName})\n`);

            const likedBy = await User.find({ likedUsers: user._id }).select('email firstName lastName').lean();
            result += `Liked By (${likedBy.length} users):\n`;
            likedBy.forEach(u => result += `  - ${u.email} (${u.firstName} ${u.lastName})\n`);
        }
        console.log("FINAL_RESULT_START");
        console.log(result);
        console.log("FINAL_RESULT_END");
        process.exit(0);

    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    } finally {
        await mongoose.connection.close();
    }
}

run();
