const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
require('dotenv').config();
const User = require('./models/User');
const Message = require('./models/Message');
const Notification = require('./models/Notification');
const Status = require('./models/Status');
const Event = require('./models/Event');

const app = express();

process.on('uncaughtException', (err) => {
    console.error('🔥 CRITICAL: Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('🔥 CRITICAL: Unhandled Rejection at:', promise, 'reason:', reason);
});

const http = require('http').Server(app);
const io = require('socket.io')(http, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Socket.io User Management
const onlineUsers = new Map(); // Store userId -> socketId

io.on('connection', (socket) => {
    console.log('🔌 A user connected:', socket.id);

    socket.on('user_online', async (userId) => {
        if (!userId) return;
        socket.userId = userId;
        onlineUsers.set(userId, socket.id);
        console.log(`👤 User ${userId} is online`);

        // Broadcast to all that this user is online
        io.emit('status_change', { userId, isOnline: true });

        try {
            await User.findByIdAndUpdate(userId, { isOnline: true, lastActive: Date.now() });
        } catch (err) {
            console.error('Error updating status:', err);
        }
    });

    socket.on('typing', (data) => {
        // data should contain { senderId, receiverId, senderName }
        const receiverSocketId = onlineUsers.get(data.receiverId);
        if (receiverSocketId) {
            io.to(receiverSocketId).emit('user_typing', {
                senderId: data.senderId,
                senderName: data.senderName
            });
        }
    });

    socket.on('stop_typing', (data) => {
        const receiverSocketId = onlineUsers.get(data.receiverId);
        if (receiverSocketId) {
            io.to(receiverSocketId).emit('user_stop_typing', {
                senderId: data.senderId
            });
        }
    });

    // ─── WebRTC Call Signaling ───────────────────────────────────────────
    // Relay call offer to the target user
    socket.on('call_offer', (data) => {
        const { to, from, offer, callType, callerName, callerAvatar } = data;
        console.log(`📞 call_offer received: ${from} → ${to} (${callType})`);
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) {
            console.log(`📞 Forwarding incoming_call to socket ${targetSocket}`);
            io.to(targetSocket).emit('incoming_call', { from, offer, callType, callerName, callerAvatar });
        } else {
            console.log(`📞 Target user ${to} is NOT online, cannot forward call`);
        }
    });

    // Relay call answer back to caller
    socket.on('call_answer', (data) => {
        const { to, answer } = data;
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) {
            io.to(targetSocket).emit('call_answered', { answer });
        }
    });

    // Relay ICE candidate
    socket.on('call_ice_candidate', (data) => {
        const { to, candidate } = data;
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) {
            io.to(targetSocket).emit('call_ice_candidate', { candidate });
        }
    });

    // Relay call rejection
    socket.on('call_reject', (data) => {
        const { to } = data;
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) {
            io.to(targetSocket).emit('call_rejected');
        }
    });

    // Relay call end
    socket.on('call_end', (data) => {
        const { to } = data;
        const targetSocket = onlineUsers.get(to);
        if (targetSocket) {
            io.to(targetSocket).emit('call_ended');
        }
    });
    // ────────────────────────────────────────────────────────────────────

    socket.on('disconnect', async () => {
        if (socket.userId) {
            console.log(`🔌 User ${socket.userId} disconnected`);
            onlineUsers.delete(socket.userId);

            // Broadcast offline status
            io.emit('status_change', { userId: socket.userId, isOnline: false });

            try {
                await User.findByIdAndUpdate(socket.userId, { isOnline: false, lastActive: Date.now() });
            } catch (err) {
                console.error('Error updating status:', err);
            }
        }
    });
});

// Middleware
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// MongoDB Connection
const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

// Enable buffering (default) to handle temporary connection blips gracefully
mongoose.set('bufferCommands', true);

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Cloudflare R2 Client
const r2Client = new S3Client({
    region: "auto",
    endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: {
        accessKeyId: process.env.CLOUDFLARE_ACCESS_KEY_ID,
        secretAccessKey: process.env.CLOUDFLARE_SECRET_ACCESS_KEY,
    },
});

const connectDB = async () => {
    try {
        await mongoose.connect(uri, {
            serverSelectionTimeoutMS: 5000, // Reduced from 60s to fail faster during glitches
            connectTimeoutMS: 10000,
            socketTimeoutMS: 45000,
        });
        console.log("✅ Successfully connected to MongoDB Matchchayn!");
    } catch (err) {
        console.error("❌ MongoDB connection error:", err.message);
        // Don't exit process, let it retry or wait for next request
    }
};

connectDB();

// Health check middleware to ensure DB is connected before processing requests
const checkDBConnection = (req, res, next) => {
    if (mongoose.connection.readyState !== 1) {
        return res.status(503).json({
            message: 'Database connection is currently unavailable. Please try again in secondary.'
        });
    }
    next();
};

app.use('/api', checkDBConnection);

// Auth Routes
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        let user = await User.findOne({ email });

        if (user && user.isVerified) {
            return res.status(400).json({ message: 'Email already registered and verified' });
        }

        if (!user) {
            user = new User({ email });
        }

        // Generate 4-digit OTP
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
        await user.save();

        console.log(`📩 OTP for ${email}: ${otp}`); // Log for testing

        // Send Email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Matchchayn Verification Code',
            text: `Your verification code is: ${otp}. It will expire in 10 minutes.`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                    <h2 style="color: #6d28d9; text-align: center;">Welcome to Matchchayn</h2>
                    <p>Thank you for signing up! Use the code below to verify your email address:</p>
                    <div style="background: #f3f4f6; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #1f2937; margin: 20px 0; border-radius: 8px;">
                        ${otp}
                    </div>
                    <p style="font-size: 14px; color: #6b7280; text-align: center;">This code will expire in 10 minutes. If you did not request this, please ignore this email.</p>
                </div>
            `
        };

        try {
            console.log(`📤 Attempting to send OTP email to: ${email}...`);
            await transporter.sendMail(mailOptions);
            console.log(`✅ OTP email sent successfully to: ${email}`);
            res.json({ message: 'OTP sent to your email' });
        } catch (mailErr) {
            console.error('❌ Nodemailer Error for send-otp:', mailErr);
            res.status(500).json({ message: 'Error sending email: ' + mailErr.message });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        res.json({ message: 'OTP verified successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, otp } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid session or expired OTP' });
        }

        user.password = password;
        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({
            token,
            user: { id: user._id, email: user.email }
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(`🔑 Login attempt for: ${email}`);

        const user = await User.findOne({ email });
        if (!user) {
            console.log(`❌ Login failed: User not found (${email})`);
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        if (!user.isVerified) {
            console.log(`❌ Login failed: Account not verified (${email})`);
            return res.status(400).json({ message: 'Account not verified' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            console.log(`❌ Login failed: Password mismatch (${email})`);
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });

        const userResponse = user.toObject();
        delete userResponse.password;

        console.log(`✅ Login successful: ${email}`);
        res.json({
            token,
            user: userResponse
        });
    } catch (err) {
        console.error('🔥 Login Route Error:', err);
        res.status(500).json({ message: err.message });
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};

app.get('/api/interests', async (req, res) => {
    // Static list of interests for the dating app
    const interests = [
        { id: '1', name: 'Web3' },
        { id: '2', name: 'Crypto' },
        { id: '3', name: 'NFTs' },
        { id: '4', name: 'DeFi' },
        { id: '5', name: 'DAO' },
        { id: '6', name: 'AI' },
        { id: '7', name: 'Gaming' },
        { id: '8', name: 'Coding' },
        { id: '9', name: 'Music' },
        { id: '10', name: 'Art' },
        { id: '11', name: 'Travel' },
        { id: '12', name: 'Fitness' },
        { id: '13', name: 'Coffee' },
        { id: '14', name: 'Reading' },
        { id: '15', name: 'Startups' }
    ];
    res.json(interests);
});

app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { firstName, lastName, username, gender, dateOfBirth, city, country, relationshipStatus, bio, avatarUrl } = req.body;
        const user = await User.findById(req.user.id);

        if (!user) return res.status(404).json({ message: 'User not found' });

        user.firstName = firstName || user.firstName;
        user.lastName = lastName || user.lastName;
        user.username = username || user.username;
        user.gender = gender || user.gender;
        user.dateOfBirth = dateOfBirth || user.dateOfBirth;
        user.city = city || user.city;
        user.country = country || user.country;
        user.relationshipStatus = relationshipStatus || user.relationshipStatus;
        user.bio = bio || user.bio;
        user.avatarUrl = avatarUrl || user.avatarUrl;
        user.onboardingStatus = 'profile_created';

        await user.save();
        res.json({ message: 'Profile updated successfully', user });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/user/interests', authenticateToken, async (req, res) => {
    try {
        const { interests } = req.body;
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        user.interests = interests;
        user.onboardingStatus = 'interests_selected';
        await user.save();
        res.json({ message: 'Interests updated successfully', user });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Cloudflare R2 Presigned URL Generation
app.post('/api/media/presigned-url', authenticateToken, async (req, res) => {
    try {
        const { fileName, fileType } = req.body;
        const key = `uploads/${req.user.id}/${Date.now()}-${fileName}`;

        const command = new PutObjectCommand({
            Bucket: process.env.CLOUDFLARE_BUCKET_NAME,
            Key: key,
            ContentType: fileType,
        });

        const uploadUrl = await getSignedUrl(r2Client, command, { expiresIn: 3600 });
        const publicUrl = `${process.env.CLOUDFLARE_PUBLIC_DOMAIN}/${key}`;

        res.json({ uploadUrl, publicUrl });
    } catch (err) {
        console.error('Presigned URL Error:', err);
        res.status(500).json({ message: 'Failed to generate upload URL' });
    }
});

app.post('/api/user/preferences', authenticateToken, async (req, res) => {
    try {
        const { preferences } = req.body;
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        user.preferences = { ...user.preferences, ...preferences };
        user.onboardingStatus = 'preferences_set';
        await user.save();
        res.json({ message: 'Preferences updated successfully', user });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/user/media', authenticateToken, async (req, res) => {
    try {
        const { avatarUrl, secondaryPhotoUrl, thirdPhotoUrl, videoUrl } = req.body;
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        if (avatarUrl) user.avatarUrl = avatarUrl;
        if (secondaryPhotoUrl) user.secondaryPhotoUrl = secondaryPhotoUrl;
        if (thirdPhotoUrl) user.thirdPhotoUrl = thirdPhotoUrl;
        if (videoUrl) user.videoUrl = videoUrl;

        user.onboardingStatus = 'completed';
        await user.save();
        res.json({ message: 'Media assets updated successfully', user });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        console.log('--- Google Auth Request ---');
        console.log('Token starts with:', token ? token.substring(0, 10) : 'null');

        let email;

        // Simple heuristic: ID tokens are usually long JWTs (3 parts), Access tokens often start with ya29
        if (token && token.includes('.')) {
            console.log('Attempting ID Token verification...');
            try {
                const ticket = await client.verifyIdToken({
                    idToken: token,
                    audience: GOOGLE_CLIENT_ID,
                });
                email = ticket.getPayload().email;
                console.log('ID Token verified successfully');
            } catch (idErr) {
                console.warn('ID Token verification failed:', idErr.message);
            }
        }

        if (!email) {
            console.log('Attempting Access Token verification via getTokenInfo...');
            try {
                const tokenInfo = await client.getTokenInfo(token);
                email = tokenInfo.email;
                console.log('Access Token verified successfully');
            } catch (accErr) {
                console.error('Access Token verification failed:', accErr.message);
                throw new Error('Invalid Google token (tried both ID and Access token formats)');
            }
        }

        if (!email) {
            throw new Error('Could not retrieve email from Google token');
        }

        let user = await User.findOne({ email });

        if (!user) {
            console.log('Creating new user for:', email);
            user = new User({
                email,
                isVerified: true,
                onboardingStatus: 'started'
            });
            await user.save();
        }

        const jwtToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
        console.log('Google Auth Successful for:', email);
        res.json({
            token: jwtToken,
            user: { id: user._id, email: user.email }
        });
    } catch (err) {
        console.error('Final Google Auth Error:', err.message);
        res.status(400).json({ message: 'Google authentication failed: ' + err.message });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User with this email not found' });
        }

        // 24 Hour Security Check
        if (user.lastPasswordReset) {
            const twentyFourHours = 24 * 60 * 60 * 1000;
            const timeSinceLastReset = Date.now() - new Date(user.lastPasswordReset).getTime();

            if (timeSinceLastReset < twentyFourHours) {
                const hoursLeft = Math.ceil((twentyFourHours - timeSinceLastReset) / (60 * 60 * 1000));
                return res.status(429).json({
                    message: `Security Lock: You can only reset your password once every 24 hours. Please try again in ${hoursLeft} hours.`
                });
            }
        }

        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000;
        await user.save();

        console.log(`📩 Password Reset OTP for ${email}: ${otp}`);

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Matchchayn Password Reset',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                    <h2 style="color: #6d28d9; text-align: center;">Password Reset Request</h2>
                    <p>You requested a password reset. Use the code below to reset your password:</p>
                    <div style="background: #f3f4f6; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #1f2937; margin: 20px 0; border-radius: 8px;">
                        ${otp}
                    </div>
                    <p style="font-size: 14px; color: #6b7280; text-align: center;">This code will expire in 10 minutes.</p>
                </div>
            `
        };

        try {
            console.log(`📤 Attempting to send Reset email to: ${email}...`);
            await transporter.sendMail(mailOptions);
            console.log(`✅ Reset email sent successfully to: ${email}`);
            res.json({ message: 'Reset OTP sent to your email' });
        } catch (mailErr) {
            console.error('❌ Nodemailer Error for forgot-password:', mailErr);
            res.status(500).json({ message: 'Error sending email: ' + mailErr.message });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        user.password = newPassword;
        user.otp = undefined;
        user.otpExpires = undefined;
        user.lastPasswordReset = Date.now();
        await user.save();

        res.json({ message: 'Password reset successful. You can now login.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Matching & Likes System
app.get('/api/user/matches-feed', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const { preferences } = user;
        const query = {
            _id: { $ne: user._id, $nin: user.likedUsers }, // Not self AND not already liked
            onboardingStatus: 'completed' // Only show users who finished onboarding
        };

        // Fetch a pool of 100 potential matches to sort
        let feed = await User.find(query)
            .limit(100)
            .select('firstName lastName bio city country gender dateOfBirth relationshipStatus avatarUrl secondaryPhotoUrl videoUrl interests isOnline')
            .lean();

        // Sorting Algorithm
        feed = feed.sort((a, b) => {
            // 1. Prioritize profiles with videos
            const hasVideoA = a.videoUrl ? 1 : 0;
            const hasVideoB = b.videoUrl ? 1 : 0;
            if (hasVideoA !== hasVideoB) {
                return hasVideoB - hasVideoA;
            }

            // 2. Secondary: Sort by shared interests
            if (user.interests && user.interests.length > 0) {
                const sharedA = a.interests.filter(i => user.interests.includes(i)).length;
                const sharedB = b.interests.filter(i => user.interests.includes(i)).length;
                return sharedB - sharedA;
            }
            return 0;
        });

        res.json(feed.slice(0, 20));
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/user/like', authenticateToken, async (req, res) => {
    try {
        const { targetUserId } = req.body;
        const user = await User.findById(req.user.id);
        const targetUser = await User.findById(targetUserId);

        if (!targetUser) return res.status(404).json({ message: 'Target user not found' });

        // Add to likedUsers if not already there
        if (!user.likedUsers.includes(targetUserId)) {
            user.likedUsers.push(targetUserId);
            await user.save();

            // Create a "like" notification for the target user
            await new Notification({
                recipient: targetUserId,
                sender: user._id,
                type: 'like'
            }).save();
        }

        // Check if it's a mutual match
        if (targetUser.likedUsers.includes(user._id)) {
            // It's a match!
            if (!user.matches.includes(targetUserId)) {
                user.matches.push(targetUserId);
                await user.save();
            }
            if (!targetUser.matches.includes(user._id)) {
                targetUser.matches.push(user._id);
                await targetUser.save();
            }

            // Create "match" notifications for BOTH users
            await new Notification({
                recipient: targetUserId,
                sender: user._id,
                type: 'match'
            }).save();

            await new Notification({
                recipient: user._id,
                sender: targetUserId,
                type: 'match'
            }).save();

            return res.json({ message: 'It\'s a Match! 💖', isMatch: true });
        }

        res.json({ message: 'Liked successfully', isMatch: false });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/user/likes', authenticateToken, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        const likes = await User.find({
            likedUsers: req.user.id,
            _id: { $nin: me.likedUsers }
        }).select('firstName lastName avatarUrl bio gender city interests isOnline');
        res.json(likes);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/user/liked-profiles', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).populate('likedUsers', 'firstName lastName avatarUrl bio gender city isOnline');
        res.json(user.likedUsers);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/user/matches', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).populate('matches', 'firstName lastName avatarUrl bio gender city lastSeen isOnline');
        res.json(user.matches);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
    console.log(`🔔 Fetching notifications for user: ${req.user.id}`);
    try {
        const notifications = await Notification.find({ recipient: req.user.id })
            .populate('sender', 'firstName lastName avatarUrl')
            .sort({ createdAt: -1 })
            .limit(50);
        res.json(notifications);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/notifications/read', authenticateToken, async (req, res) => {
    try {
        await Notification.updateMany(
            { recipient: req.user.id, isRead: false },
            { $set: { isRead: true } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Messaging
app.get('/api/messages/:otherUserId', authenticateToken, async (req, res) => {
    try {
        const messages = await Message.find({
            $or: [
                { sender: req.user.id, receiver: req.params.otherUserId },
                { sender: req.params.otherUserId, receiver: req.user.id }
            ]
        }).sort({ createdAt: 1 });
        res.json(messages);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { receiverId, content, messageType } = req.body;
        const message = new Message({
            sender: req.user.id,
            receiver: receiverId,
            content,
            messageType: messageType || 'text'
        });
        await message.save();

        // Also create a notification
        await new Notification({
            recipient: receiverId,
            sender: req.user.id,
            type: 'message',
            relatedMessage: message._id
        }).save();

        res.status(201).json(message);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
    try {
        const message = await Message.findById(req.params.id);
        if (!message) return res.status(404).json({ message: 'Message not found' });

        // Only allow sender to delete their own messages
        if (message.sender.toString() !== req.user.id) {
            return res.status(403).json({ message: 'Not authorized to delete this message' });
        }

        await Message.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Message deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/conversations', authenticateToken, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        // Find users that are matches
        const matches = await User.find({ _id: { $in: me.matches } })
            .select('firstName lastName avatarUrl bio isOnline');

        const conversations = await Promise.all(matches.map(async (match) => {
            const lastMessage = await Message.findOne({
                $or: [
                    { sender: me._id, receiver: match._id },
                    { sender: match._id, receiver: me._id }
                ]
            }).sort({ createdAt: -1 });

            return {
                otherUser: match,
                lastMessage: lastMessage
            };
        }));

        res.json(conversations);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Status System
app.post('/api/status', authenticateToken, async (req, res) => {
    try {
        const { imageUrl } = req.body;
        if (!imageUrl) return res.status(400).json({ message: 'Image URL is required' });

        const status = new Status({
            user: req.user.id,
            imageUrl,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
        });

        await status.save();
        res.status(201).json(status);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/status/feed', authenticateToken, async (req, res) => {
    try {
        const me = await User.findById(req.user.id);
        const matchIds = me.matches || [];

        // Include my own status and my matches' statuses
        const userIdsToFetch = [req.user.id, ...matchIds];

        const statuses = await Status.find({
            user: { $in: userIdsToFetch },
            expiresAt: { $gt: new Date() }
        })
            .populate('user', 'firstName lastName avatarUrl')
            .sort({ createdAt: -1 });

        // Group by user so we only show the latest status per user in the tray, 
        // or we could return all and let frontend decide.
        // Let's return all for now.
        res.json(statuses);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// Event System
app.get('/api/events', authenticateToken, async (req, res) => {
    try {
        const events = await Event.find()
            .populate('createdBy', 'firstName lastName avatarUrl')
            .populate('attendees', 'firstName lastName avatarUrl')
            .sort({ date: 1 });
        res.json(events);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/events/:id', authenticateToken, async (req, res) => {
    try {
        const event = await Event.findById(req.params.id)
            .populate('createdBy', 'firstName lastName avatarUrl')
            .populate('attendees', 'firstName lastName avatarUrl');
        if (!event) return res.status(404).json({ message: 'Event not found' });
        res.json(event);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/events', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (user.role !== 'admin') {
            return res.status(403).json({ message: 'Only admins can create events' });
        }

        const { title, description, date, endDate, location, imageUrl, maxAttendees } = req.body;
        const event = new Event({
            title,
            description,
            date,
            endDate,
            location,
            imageUrl,
            maxAttendees,
            createdBy: req.user.id
        });

        await event.save();
        res.status(201).json(event);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.patch('/api/events/:id', authenticateToken, async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        if (!event) return res.status(404).json({ message: 'Event not found' });

        // Only creator or admin can update
        const user = await User.findById(req.user.id);
        if (event.createdBy.toString() !== req.user.id && user.role !== 'admin') {
            return res.status(403).json({ message: 'Not authorized to edit this event' });
        }

        const { title, description, date, endDate, location, imageUrl, maxAttendees } = req.body;

        if (title) event.title = title;
        if (description) event.description = description;
        if (date) event.date = date;
        if (endDate) event.endDate = endDate;
        if (location) event.location = location;
        if (imageUrl) event.imageUrl = imageUrl;
        if (maxAttendees) event.maxAttendees = maxAttendees;

        await event.save();
        res.json(event);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.delete('/api/events/:id', authenticateToken, async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        if (!event) return res.status(404).json({ message: 'Event not found' });

        // Only creator or admin can delete
        const user = await User.findById(req.user.id);
        if (event.createdBy.toString() !== req.user.id && user.role !== 'admin') {
            return res.status(403).json({ message: 'Not authorized to delete this event' });
        }

        await Event.findByIdAndDelete(req.params.id);
        res.json({ message: 'Event deleted successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/events/:id/join', authenticateToken, async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        if (!event) return res.status(404).json({ message: 'Event not found' });

        if (event.attendees.includes(req.user.id)) {
            return res.status(400).json({ message: 'Already joined this event' });
        }

        if (event.attendees.length >= event.maxAttendees) {
            return res.status(400).json({ message: 'Event is full' });
        }

        event.attendees.push(req.user.id);
        await event.save();

        res.json({ message: 'Successfully joined the event', event });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Basic Route
app.get('/', (req, res) => {
    res.send('Matchchayn API is running...');
});

// Final Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('🔥 Global Error Handler:', err);

    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ message: 'Invalid JSON payload. Please check your request formatting.' });
    }

    res.status(err.status || 500).json({
        message: err.message || 'An internal server error occurred',
        error: process.env.NODE_ENV === 'development' ? err : {}
    });
});

// Start Server
const PORT = process.env.PORT || 5000;
if (process.env.NODE_ENV !== 'production') {
    http.listen(PORT, () => {
        console.log(`🚀 Server is running on port ${PORT}`);
    });
} else {
    // In Vercel environments, we don't start the listener ourselves, we export it.
    console.log(`🚀 Exporting Vercel Serverless API`);
}

module.exports = app;
