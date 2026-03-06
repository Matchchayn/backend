
const jwt = require('jsonwebtoken');
require('dotenv').config();

const token = jwt.sign(
    { id: '699b1a8b57ae2871e1e9f83f' }, // Victoria's ID
    process.env.JWT_SECRET,
    { expiresIn: '1d' }
);

require('fs').writeFileSync('current_token.txt', token);
console.log('Token written to current_token.txt');
