
require('dotenv').config();
const mongoose = require('mongoose');

async function listCols() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to DB');
        const collections = await mongoose.connection.db.listCollections().toArray();
        console.log('Collections:', collections.map(c => c.name));
    } catch (err) {
        console.error(err);
    } finally {
        await mongoose.disconnect();
    }
}
listCols();
