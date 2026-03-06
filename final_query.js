const mongoose = require('mongoose');
const uri = "mongodb+srv://josephakpansunday_db_user:Y7NIxaetH1p266HC@matchchayn.ibgx3ys.mongodb.net/Matchchayn?retryWrites=true&w=majority";

const userSchema = new mongoose.Schema({
    email: String,
    firstName: String,
    lastName: String,
    likedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    matches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
});

const User = mongoose.model('User', userSchema);

async function run() {
    try {
        await mongoose.connect(uri);
        const email = 'victoriialinda998@gmail.com';
        const user = await User.findOne({ email }).populate('matches', 'email firstName lastName').lean();

        if (!user) {
            console.log("User not found: " + email);
            process.exit(0);
        }

        console.log(`\nACCOUNT: ${user.email} (${user.firstName} ${user.lastName})`);

        console.log(`\nMATCHES (${user.matches ? user.matches.length : 0}):`);
        if (user.matches && user.matches.length > 0) {
            user.matches.forEach((m, i) => {
                console.log(`${i + 1}. ${m.email} (${m.firstName} ${m.lastName})`);
            });
        }

        const likedBy = await User.find({ likedUsers: user._id }).select('email firstName lastName').lean();
        console.log(`\nLIKED BY (${likedBy.length} users who you haven't matched with yet):`);
        likedBy.forEach((u, i) => {
            console.log(`${i + 1}. ${u.email} (${u.firstName} ${u.lastName})`);
        });

        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}
run();
