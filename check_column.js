
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI);
    try {
        await client.connect();
        const db = client.db('Matchchayn');
        const users = db.collection('users');

        const column = await users.findOne({ firstName: 'Column' });
        console.log('Column user:', JSON.stringify(column, null, 2));
    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
    }
}
run();
