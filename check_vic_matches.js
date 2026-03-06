
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');

        const victoria = await users.findOne({ email: 'victoriialinda998@gmail.com' });
        console.log('Victoria matches count:', victoria.matches ? victoria.matches.length : 0);

        if (victoria.matches && victoria.matches.length > 0) {
            const matches = await users.find({ _id: { $in: victoria.matches } }).toArray();
            console.log('Matches video URLs:');
            matches.forEach(m => {
                console.log(` - ${m.firstName}: ${m.videoUrl || 'NONE'}`);
            });
        }
    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
run();
