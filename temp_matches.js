const mongoose = require('mongoose');
const uri = "mongodb+srv://josephakpansunday_db_user:Y7NIxaetH1p266HC@matchchayn.ibgx3ys.mongodb.net/Matchchayn?retryWrites=true&w=majority";

const userSchema = new mongoose.Schema({
    email: String,
    firstName: String,
    lastName: String,
    matches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
});

const User = mongoose.model('User', userSchema);

async function run() {
    try {
        await mongoose.connect(uri);
        const user = await User.findById('699b1a8b57ae2871e1e9f83f').populate('matches', 'email firstName lastName').lean();

        console.log(`\nMatches for ${user.email} (${user.firstName} ${user.lastName}):`);
        if (user.matches && user.matches.length > 0) {
            user.matches.forEach((m, i) => {
                console.log(`${i + 1}. ${m.email} (${m.firstName} ${m.lastName})`);
            });
        } else {
            console.log("No matches found.");
        }

        const likedBy = await User.find({ likedUsers: '699b1a8b57ae2871e1e9f83f' }).select('email firstName lastName').lean();
        console.log(`\nLiked by ${likedBy.length} users:`);
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
