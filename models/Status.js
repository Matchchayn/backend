const mongoose = require('mongoose');

const statusSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    imageUrl: {
        type: String,
        required: true
    },
    expiresAt: {
        type: Date,
        required: true,
        index: { expires: 0 } // This will automatically delete the document at the specified time
    }
}, { timestamps: true });

module.exports = mongoose.model('Status', statusSchema);
