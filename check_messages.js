
const { MongoClient } = require('mongodb');
require('dotenv').config();

async function run() {
    const client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
    try {
        await client.connect();
        const db = client.db('Matchchayn');

        const victoriaId = "699b1a8b57ae2871e1e9f83f";
        const messages = await db.collection('messages').find({
            $or: [{ sender: victoriaId }, { receiver: victoriaId }]
        }).toArray();

        console.log(`Victoria has ${messages.length} messages.`);

        const convos = await db.collection('conversations').find({
            participants: victoriaId
        }).toArray();
        console.log(`Victoria has ${convos.length} conversations in the conversations collection.`);

    } catch (err) {
        console.error(err);
    } finally {
        await client.close();
        process.exit(0);
    }
}
run();
