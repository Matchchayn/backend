const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const mailOptions = {
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_USER, // Send to self for test
    subject: 'Matchchayn Email Test',
    text: 'If you receive this, the email configuration is working.'
};

console.log('Testing email transport...');
transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
        console.error('❌ Test Failed:', error.message);
    } else {
        console.log('✅ Test Succeeded:', info.response);
    }
    process.exit();
});
