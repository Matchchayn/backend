require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const dns = require('dns');

console.log('--- Startup Config Check ---');
console.log('MONGODB_URI present:', !!process.env.MONGODB_URI);
console.log('JWT_SECRET present:', !!process.env.JWT_SECRET);
console.log('R2 Config present:', !!(process.env.CLOUDFLARE_ACCOUNT_ID && process.env.CLOUDFLARE_BUCKET_NAME));
console.log('---------------------------');

// Force IPv4 as first priority (Fixes Render ENETUNREACH errors)
if (dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
}

const { Resend } = require('resend');
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const User = require('./models/User');
const Message = require('./models/Message');
const Notification = require('./models/Notification');
const Status = require('./models/Status');
const Event = require('./models/Event');

// Keep buffering on so brief disconnects can be smoothed by reconnect logic
mongoose.set('bufferCommands', true);

const app = express();

process.on('uncaughtException', (err) => {
    console.error('🔥 CRITICAL: Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('🔥 CRITICAL: Unhandled Rejection at:', promise, 'reason:', reason);
});

const server = require('http').createServer(app);
const { Server } = require('socket.io');
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    },
    pingTimeout: 60000,
    pingInterval: 25000,
    connectTimeout: 45000
});

// Socket.io User Management
const onlineUsers = new Map(); // Store userId -> socketId
const matchesCache = new Map(); // Store userId -> { data, timestamp }
const CACHE_TTL = 30000; // 30 seconds

function getCachedMatches(userId) {
    const cached = matchesCache.get(userId);
    if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
        return cached.data;
    }
    return null;
}

function setCachedMatches(userId, data) {
    matchesCache.set(userId, { data, timestamp: Date.now() });
}

function invalidateUserCache(userId) {
    matchesCache.delete(userId);
}

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
            // Only try to update DB if connected, otherwise we just rely on the in-memory onlineUsers Map
            if (mongoose.connection.readyState === 1) {
                await User.findByIdAndUpdate(userId, { isOnline: true, lastActive: Date.now() });
            } else {
                console.warn(`⚠️ DB not connected. Skipping isOnline update for user ${userId}`);
            }
        } catch (err) {
            console.error('Error updating online status:', err.message);
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
                if (mongoose.connection.readyState === 1) {
                    await User.findByIdAndUpdate(socket.userId, { isOnline: false, lastActive: Date.now() });
                }
            } catch (err) {
                console.error('Error updating offline status:', err.message);
            }
        }
    });
});

// Middleware
app.use(compression());

// Moved Global Request Logger below initial middlewares for better req.user visibility
app.use((req, res, next) => {
    if (req.path.startsWith('/api') && req.path !== '/api/health') {
        // We log after auth middleware usually or just accept it's unauthenticated for now
    }
    next();
});

// Improved CORS: Allow both localhost (dev) and production domains
const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:5173',
    'https://matchchayn.com',
    'https://www.matchchayn.com',
    'https://zoological-celebration-production-e24f.up.railway.app'
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1 || origin.includes('railway.app')) {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            callback(null, true); // Still allow but log for now to debug
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '50mb' }));

// MongoDB Connection
const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

// Nodemailer setup
const transporter = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
        user: process.env.EMAIL_USER2,
        pass: process.env.EMAIL_PASS2
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

/**
 * More robust helper to generate signed URLs for objects stored in Cloudflare R2
 */
async function signUrl(originalUrl) {
    if (!originalUrl) return originalUrl;
    
    // Auto-fix for common typo in R2 bucket domain: 446 instead of 46
    let urlToSign = String(originalUrl);
    if (urlToSign.includes('446.r2.dev')) {
        urlToSign = urlToSign.replace('446.r2.dev', '46.r2.dev');
    }

    const isR2 = urlToSign.includes('r2.cloudflarestorage.com') ||
                 urlToSign.includes('pub-') ||
                 urlToSign.includes('.r2.dev');

    if (!isR2) return urlToSign;

    try {
        const url = new URL(urlToSign);
        // Key is the pathname without the leading slash
        const rawKey = url.pathname.startsWith('/') ? url.pathname.substring(1) : url.pathname;

        // Fully decode the key - handles both single (%20) and double (%2520) encoding
        let decodedKey = rawKey;
        for (let i = 0; i < 3; i++) {
            try {
                const next = decodeURIComponent(decodedKey);
                if (next === decodedKey) break; // stable
                decodedKey = next;
            } catch (e) { break; }
        }

        const command = new GetObjectCommand({
            Bucket: process.env.CLOUDFLARE_BUCKET_NAME,
            Key: decodedKey
        });

        // Generate a temporary signed URL (valid for 1 hour)
        return await getSignedUrl(r2Client, command, { expiresIn: 3600 });
    } catch (e) {
        console.error(`[SignUrl] FAILED:`, e.message);
        return originalUrl;
    }
}

/**
 * Signs all media fields for a user object and ensures consistent ID fields.
 */
async function signUserMedia(userObj) {
    if (!userObj) return userObj;
    
    // Convert Mongoose doc to plain object if needed
    const data = (userObj.toObject && typeof userObj.toObject === 'function') 
                 ? userObj.toObject() 
                 : JSON.parse(JSON.stringify(userObj));

    // Ensure ID consistency
    if (data._id) {
        data.id = data._id.toString();
        data._id = data._id.toString();
    }

    // List of media fields to sign
    const mediaFields = ['avatarUrl', 'secondaryPhotoUrl', 'thirdPhotoUrl', 'videoUrl'];
    
    // Fetch all signed URLs in parallel
    const signedUrls = await Promise.all(
        mediaFields.map(field => data[field] ? signUrl(data[field]) : null)
    );

    // Reattach them to the user object
    mediaFields.forEach((field, index) => {
        if (signedUrls[index]) {
            data[field] = signedUrls[index];
        }
    });

    return data;
}

/** For list views (matches, likes): sign only avatarUrl so lists load faster. */
async function signUserMediaList(userObj) {
    if (!userObj) return userObj;
    const data = (userObj.toObject && typeof userObj.toObject === 'function')
        ? userObj.toObject()
        : JSON.parse(JSON.stringify(userObj));
    if (data._id) {
        data.id = data._id.toString();
        data._id = data._id.toString();
    }
    if (data.avatarUrl) data.avatarUrl = await signUrl(data.avatarUrl);
    return data;
}

// Deprecated in favor of signUserMedia, but kept for compatibility during transition
async function signUserVideos(userObj) {
    return signUserMedia(userObj);
}

const MONGODB_OPTIONS = {
    serverSelectionTimeoutMS: 30000,  // give Atlas replica set more time on slow networks
    connectTimeoutMS: 30000,
    socketTimeoutMS: 90000,
    maxPoolSize: 50,
    heartbeatFrequencyMS: 10000,
};

const connectDB = async () => {
    try {
        await mongoose.connect(uri, MONGODB_OPTIONS);
        console.log("✅ Successfully connected to MongoDB Matchchayn!");
        return true;
    } catch (err) {
        console.error("❌ MongoDB connection error:", err.message);
        return false;
    }
};

// Startup: retry connection with backoff (handles cold start / slow network)
const startDbWithRetry = async (maxAttempts = 5) => {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        if (await connectDB()) return;
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 15000);
        console.log(`⏳ MongoDB retry ${attempt}/${maxAttempts} in ${delay}ms...`);
        await new Promise((r) => setTimeout(r, delay));
    }
    console.warn("⚠️ MongoDB could not connect after retries. Server will run; DB will retry on disconnect.");
};

// Reconnect when connection drops (e.g. Atlas timeout, ReplicaSetNoPrimary)
let reconnectTimeout = null;
const scheduleReconnect = () => {
    if (mongoose.connection.readyState === 1) return;
    if (reconnectTimeout) return;
    reconnectTimeout = setTimeout(async () => {
        reconnectTimeout = null;
        console.log("🔄 Attempting MongoDB reconnect...");
        await connectDB();
    }, 5000);
};

mongoose.connection.on("disconnected", () => {
    console.warn("⚠️ MongoDB disconnected. Will attempt reconnect in 5s.");
    scheduleReconnect();
});
mongoose.connection.on("error", (err) => {
    console.error("⚠️ MongoDB connection error (event):", err.message);
    scheduleReconnect();
});

startDbWithRetry();

// Health check middleware to ensure DB is connected before processing requests
const checkDBConnection = (req, res, next) => {
    // Lenient check: still error if readyState is 0 (disconnected) but allow 2/3 (connecting/disconnecting)
    if (mongoose.connection.readyState === 0) {
        return res.status(503).json({
            message: 'Database connection is currently unavailable. Please try again.'
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

        // Daily Rate Limit for Signup (2 times per day)
        const today = new Date().setHours(0, 0, 0, 0);
        const lastSent = user.lastOtpSent ? new Date(user.lastOtpSent).setHours(0, 0, 0, 0) : null;

        if (lastSent === today) {
            if (user.otpCount >= 2) {
                return res.status(429).json({ message: 'Daily limit reached: You can only request 2 signup codes per day.' });
            }
            user.otpCount += 1;
        } else {
            user.otpCount = 1;
        }
        user.lastOtpSent = new Date();

        // Generate 4-digit OTP
        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp;
        user.otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
        await user.save();

        // Send Email
        const mailOptions = {
            from: `"Matchchayn" <${process.env.EMAIL_USER}>`,
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
            let emailSent = false;

            // 1. Try Resend (Main Production Method)
            if (resend) {
                try {
                    const { data, error } = await resend.emails.send({
                        from: 'Matchchayn <support@matchchayn.com>',
                        to: email,
                        subject: mailOptions.subject,
                        html: mailOptions.html
                    });

                    if (error) {
                        console.warn(`⚠️ Resend failed:`, error);
                    } else {
                        console.log(`✅ OTP email sent successfully via Resend to: ${email}`);
                        emailSent = true;
                    }
                } catch (resendErr) {
                    console.warn(`⚠️ Resend caught error:`, resendErr);
                }
            }

            // 2. Nodemailer Fallback (For Local / If Resend Fails)
            if (!emailSent) {
                await transporter.sendMail(mailOptions);
                console.log(`✅ OTP email sent successfully via Nodemailer to: ${email}`);
            }

            res.json({ message: 'OTP sent to your email' });
        } catch (mailErr) {
            console.error('❌ Email Error for send-otp:', mailErr);
            res.status(500).json({ message: 'Error sending email. Please try again later.' });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.otp !== otp || user.otpExpires < new Date()) {
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

        if (!user || user.otp !== otp || user.otpExpires < new Date()) {
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

    if (!token) {
        console.log(`[Auth] No token provided for ${req.path}`);
        return res.status(401).json({ message: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log(`[Auth] Invalid/Expired token for ${req.path}`);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        console.log(`[AUTH API] ${req.method} ${req.path} - User: ${user?.id || user?._id || 'unknown'}`);
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

        const signedUser = await signUserMedia(user);
        res.json(signedUser);
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
        // Sanitize filename to avoid weird URL encoding bugs (spaces, parens, etc)
        const safeName = fileName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
        const key = `uploads/${req.user.id}/${Date.now()}-${safeName}`;

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

        const wasAlreadyCompleted = user.onboardingStatus === 'completed';

        if (avatarUrl) user.avatarUrl = avatarUrl;
        if (secondaryPhotoUrl) user.secondaryPhotoUrl = secondaryPhotoUrl;
        if (thirdPhotoUrl) user.thirdPhotoUrl = thirdPhotoUrl;
        if (videoUrl) user.videoUrl = videoUrl;

        user.onboardingStatus = 'completed';
        await user.save();

        // Send welcome email only on first-time completion
        if (!wasAlreadyCompleted && resend && user.email) {
            const firstName = user.firstName || 'there';
            resend.emails.send({
                from: 'Matchchayn <support@matchchayn.com>',
                to: user.email,
                subject: `Welcome to Matchchayn, ${firstName}! 🎉`,
                html: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Welcome to Matchchayn</title>
</head>
<body style="margin:0;padding:0;background-color:#090a1e;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#090a1e;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg,#1a1a2e,#0d0e24);border-radius:20px;border:1px solid rgba(168,85,247,0.2);overflow:hidden;max-width:600px;width:90%;">
          
          <!-- Header -->
          <tr>
            <td align="center" style="background:linear-gradient(135deg,#7c3aed,#db2777);padding:40px 30px;">
              <p style="margin:0 0 12px 0;font-size:36px;font-weight:900;color:#fff;letter-spacing:4px;text-transform:uppercase;">MATCHCHAYN</p>
              <p style="margin:0;font-size:13px;color:rgba(255,255,255,0.8);letter-spacing:2px;text-transform:uppercase;">Match on your frequency, on-chain</p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px 40px 20px 40px;">
              <h1 style="margin:0 0 16px 0;color:#fff;font-size:26px;font-weight:800;">Hey ${firstName}! 🚀</h1>
              <p style="margin:0 0 20px 0;color:rgba(255,255,255,0.75);font-size:15px;line-height:1.7;">
                Your profile is live and you're officially part of the Matchchayn community — where meaningful connections are built on-chain.
              </p>
              <p style="margin:0 0 30px 0;color:rgba(255,255,255,0.75);font-size:15px;line-height:1.7;">
                Here's what you can do right now:
              </p>

              <!-- Feature cards -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:rgba(124,58,237,0.15);border:1px solid rgba(124,58,237,0.3);border-radius:12px;padding:18px 20px;margin-bottom:12px;display:block;">
                    <p style="margin:0 0 6px 0;color:#a78bfa;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1px;">💜 Match</p>
                    <p style="margin:0;color:rgba(255,255,255,0.7);font-size:14px;">Browse profiles and find people who vibe on your frequency.</p>
                  </td>
                </tr>
                <tr><td style="height:10px;"></td></tr>
                <tr>
                  <td style="background:rgba(219,39,119,0.15);border:1px solid rgba(219,39,119,0.3);border-radius:12px;padding:18px 20px;">
                    <p style="margin:0 0 6px 0;color:#f472b6;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1px;">💬 Connect</p>
                    <p style="margin:0;color:rgba(255,255,255,0.7);font-size:14px;">Message your matches and start real conversations — no noise, just signal.</p>
                  </td>
                </tr>
                <tr><td style="height:10px;"></td></tr>
                <tr>
                  <td style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:12px;padding:18px 20px;">
                    <p style="margin:0 0 6px 0;color:#34d399;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1px;">⛓️ On-Chain (Coming Soon)</p>
                    <p style="margin:0;color:rgba(255,255,255,0.7);font-size:14px;">Connect your Solana wallet and unlock blockchain-verified matching features.</p>
                  </td>
                </tr>
              </table>

              <!-- CTA Button -->
              <div style="text-align:center;margin:36px 0;">
                <a href="https://matchchayn.com" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#db2777);color:#fff;font-weight:800;font-size:15px;text-decoration:none;padding:14px 40px;border-radius:50px;letter-spacing:1px;text-transform:uppercase;">
                  Start Matching →
                </a>
              </div>

              <p style="color:rgba(255,255,255,0.4);font-size:13px;line-height:1.6;text-align:center;">
                You're receiving this because you just completed your Matchchayn profile.<br/>
                If this wasn't you, please <a href="mailto:support@matchchayn.com" style="color:#a78bfa;text-decoration:none;">contact us</a>.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:rgba(0,0,0,0.3);padding:20px 40px;text-align:center;border-top:1px solid rgba(168,85,247,0.1);">
              <p style="margin:0;color:rgba(255,255,255,0.2);font-size:12px;letter-spacing:1px;">© 2025 MATCHCHAYN · Match on your frequency</p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
                `
            }).catch(err => console.error('Welcome email failed:', err.message));
        }

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

            // Send welcome email to new Google users
            if (resend) {
                resend.emails.send({
                    from: 'Matchchayn <support@matchchayn.com>',
                    to: email,
                    subject: `Welcome to Matchchayn! 🎉`,
                    html: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Welcome to Matchchayn</title>
</head>
<body style="margin:0;padding:0;background-color:#090a1e;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#090a1e;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:linear-gradient(135deg,#1a1a2e,#0d0e24);border-radius:20px;border:1px solid rgba(168,85,247,0.2);overflow:hidden;max-width:600px;width:90%;">
          
          <!-- Header -->
          <tr>
            <td align="center" style="background:linear-gradient(135deg,#7c3aed,#db2777);padding:40px 30px;">
              <p style="margin:0 0 12px 0;font-size:36px;font-weight:900;color:#fff;letter-spacing:4px;text-transform:uppercase;">MATCHCHAYN</p>
              <p style="margin:0;font-size:13px;color:rgba(255,255,255,0.8);letter-spacing:2px;text-transform:uppercase;">Match on your frequency, on-chain</p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px 40px 20px 40px;">
              <h1 style="margin:0 0 16px 0;color:#fff;font-size:26px;font-weight:800;">You're in! 🚀</h1>
              <p style="margin:0 0 20px 0;color:rgba(255,255,255,0.75);font-size:15px;line-height:1.7;">
                Your Google account has been successfully connected to Matchchayn — the on-chain dating platform where meaningful connections go beyond the algorithm.
              </p>
              <p style="margin:0 0 30px 0;color:rgba(255,255,255,0.75);font-size:15px;line-height:1.7;">
                <strong style="color:#a78bfa;">Next step:</strong> Complete your profile so others can find and match with you!
              </p>

              <!-- Steps -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:rgba(124,58,237,0.15);border:1px solid rgba(124,58,237,0.3);border-radius:12px;padding:18px 20px;">
                    <p style="margin:0 0 6px 0;color:#a78bfa;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1px;">✏️ Step 1 · Build Your Profile</p>
                    <p style="margin:0;color:rgba(255,255,255,0.7);font-size:14px;">Add your name, bio, city, and what you're looking for.</p>
                  </td>
                </tr>
                <tr><td style="height:10px;"></td></tr>
                <tr>
                  <td style="background:rgba(219,39,119,0.15);border:1px solid rgba(219,39,119,0.3);border-radius:12px;padding:18px 20px;">
                    <p style="margin:0 0 6px 0;color:#f472b6;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1px;">🎯 Step 2 · Pick Your Interests</p>
                    <p style="margin:0;color:rgba(255,255,255,0.7);font-size:14px;">Select from Web3, AI, Music, Travel and more to find your frequency.</p>
                  </td>
                </tr>
                <tr><td style="height:10px;"></td></tr>
                <tr>
                  <td style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:12px;padding:18px 20px;">
                    <p style="margin:0 0 6px 0;color:#34d399;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1px;">📸 Step 3 · Upload Your Media</p>
                    <p style="margin:0;color:rgba(255,255,255,0.7);font-size:14px;">Add a photo or short video — profiles with videos get 10x more matches!</p>
                  </td>
                </tr>
              </table>

              <!-- CTA Button -->
              <div style="text-align:center;margin:36px 0;">
                <a href="https://matchchayn.com" style="display:inline-block;background:linear-gradient(135deg,#7c3aed,#db2777);color:#fff;font-weight:800;font-size:15px;text-decoration:none;padding:14px 40px;border-radius:50px;letter-spacing:1px;text-transform:uppercase;">
                  Complete My Profile →
                </a>
              </div>

              <p style="color:rgba(255,255,255,0.4);font-size:13px;line-height:1.6;text-align:center;">
                You signed in with Google at ${new Date().toUTCString()}.<br/>
                If this wasn't you, <a href="mailto:support@matchchayn.com" style="color:#a78bfa;text-decoration:none;">contact us immediately</a>.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:rgba(0,0,0,0.3);padding:20px 40px;text-align:center;border-top:1px solid rgba(168,85,247,0.1);">
              <p style="margin:0;color:rgba(255,255,255,0.2);font-size:12px;letter-spacing:1px;">© 2025 MATCHCHAYN · Match on your frequency</p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
                    `
                }).catch(err => console.error('Google signup welcome email failed:', err.message));
            }
        }

        const jwtToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
        console.log('Google Auth Successful for:', email);
        res.json({
            token: jwtToken,
            user: {
                id: user._id,
                email: user.email,
                onboardingStatus: user.onboardingStatus,
                firstName: user.firstName,
                lastName: user.lastName
            }
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

        // Daily Rate Limit for Reset (1 time per day)
        const today = new Date().setHours(0, 0, 0, 0);
        const lastResetSent = user.lastResetOtpSent ? new Date(user.lastResetOtpSent).setHours(0, 0, 0, 0) : null;

        if (lastResetSent === today) {
            if (user.resetOtpCount >= 1) {
                return res.status(429).json({ message: 'Daily limit reached: You can only request 1 password reset code per day.' });
            }
            user.resetOtpCount += 1;
        } else {
            user.resetOtpCount = 1;
        }
        user.lastResetOtpSent = new Date();

        const otp = Math.floor(1000 + Math.random() * 9000).toString();
        user.otp = otp;
        user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
        await user.save();

        const mailOptions = {
            from: `"Matchchayn" <${process.env.EMAIL_USER}>`,
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
            let emailSent = false;

            // 1. Try Resend (Main Production Method)
            if (resend) {
                try {
                    const { data, error } = await resend.emails.send({
                        from: 'Matchchayn <support@matchchayn.com>',
                        to: email,
                        subject: mailOptions.subject,
                        html: mailOptions.html
                    });

                    if (error) {
                        console.warn(`⚠️ Resend forgot-password failed:`, error);
                    } else {
                        console.log(`✅ Reset email sent successfully via Resend to: ${email}`);
                        emailSent = true;
                    }
                } catch (resendErr) {
                    console.warn(`⚠️ Resend caught forgot-password error:`, resendErr);
                }
            }

            // 2. Nodemailer Fallback (For Local / If Resend Fails)
            if (!emailSent) {
                await transporter.sendMail(mailOptions);
                console.log(`✅ Reset email sent successfully via Nodemailer to: ${email}`);
            }

            res.json({ message: 'Reset OTP sent to your email' });
        } catch (mailErr) {
            console.error('❌ Email Error for forgot-password:', mailErr);
            res.status(500).json({ message: 'Error sending email. Please try again later.' });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await User.findOne({ email });

        if (!user || user.otp !== otp || user.otpExpires < new Date()) {
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
            _id: { $ne: user._id, $nin: [...(user.likedUsers || []), ...(user.rejectedUsers || [])] }, // Not self AND not already liked/rejected
            onboardingStatus: 'completed', // Only show users who finished onboarding
            firstName: { $exists: true, $ne: '' }, // Must have a name
            avatarUrl: { $exists: true, $ne: null } // Must have a primary photo
        };

        // Filter by gender: Male sees Female, Female sees Male
        if (user.gender === 'male') {
            query.gender = 'female';
        } else if (user.gender === 'female') {
            query.gender = 'male';
        }

        // Fetch a pool of 100 potential matches to sort
        let feed = await User.find(query)
            .limit(100)
            .select('firstName avatarUrl secondaryPhotoUrl videoUrl city dateOfBirth interests bio')
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

        // Sign all media URLs and add explicit id field for frontend consistency
        const finalFeed = await Promise.all(feed.slice(0, 20).map(u => signUserMedia(u)));
        res.json(finalFeed);
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

            invalidateUserCache(user._id.toString());
            invalidateUserCache(targetUserId.toString());

            return res.json({ message: 'It\'s a Match! 💖', isMatch: true });
        }

        res.json({ message: 'Liked successfully', isMatch: false });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/user/likes', authenticateToken, async (req, res) => {
    try {
        const me = await User.findById(req.user.id).select('likedUsers rejectedUsers').lean();
        if (!me) return res.status(404).json({ message: 'User not found' });

        const myLiked = me.likedUsers || [];
        const myRejected = me.rejectedUsers || [];

        const myId = req.user.id;
        const myObjectId = new mongoose.Types.ObjectId(myId);

        // Support both string and ObjectId in the $in query for maximum robustness
        const incomingLikes = await User.find({
            likedUsers: { $in: [myId, myObjectId, String(myId)] },
            _id: { $nin: [...myLiked, ...myRejected] }
        }).select('firstName lastName avatarUrl city dateOfBirth videoUrl isOnline').lean();

        const processed = await Promise.all(incomingLikes.map(u => signUserMediaList(u)));

        res.json(processed);
    } catch (err) {
        console.error(`[API ERROR] /api/user/likes:`, err);
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/user/reject-like', authenticateToken, async (req, res) => {
    try {
        const { targetUserId } = req.body;
        const user = await User.findById(req.user.id);

        if (!user.rejectedUsers.includes(targetUserId)) {
            user.rejectedUsers.push(targetUserId);
            await user.save();
        }

        res.json({ message: 'Match request declined' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/user/liked-profiles', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('email likedUsers').lean();
        if (!user) return res.status(404).json({ message: 'User not found' });

        const likedIds = user.likedUsers || [];

        // Fetch profiles matching the IDs in the likedUsers array
        const profiles = await User.find({
            _id: { $in: likedIds }
        }).select('email firstName lastName avatarUrl city videoUrl isOnline dateOfBirth').lean();

        const processed = await Promise.all(profiles.map(u => signUserMediaList(u)));

        res.json(processed);
    } catch (err) {
        console.error(`[API ERROR] /api/user/liked-profiles:`, err);
        res.status(500).json({ message: err.message });
    }
});

app.get('/api/user/matches', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('matches').lean();
        if (!user) return res.status(404).json({ message: 'User not found' });

        const matchIds = user.matches || [];
        const profiles = await User.find({
            _id: { $in: matchIds }
        }).select('firstName lastName avatarUrl city videoUrl lastActive isOnline dateOfBirth').lean();

        const signedMatches = await Promise.all(profiles.map(u => signUserMediaList(u)));

        res.json(signedMatches);
    } catch (err) {
        console.error(`[API ERROR] /api/user/matches:`, err.message);
        res.status(500).json({ message: 'Server error retrieving matches' });
    }
});

// Notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const rawNotifications = await Notification.find({ recipient: req.user.id })
            .populate('sender', 'firstName lastName avatarUrl')
            .sort({ createdAt: -1 })
            .limit(50)
            .lean();

        const processed = await Promise.all(rawNotifications.map(async (n) => {
            if (n.sender) {
                n.sender = await signUserMediaList(n.sender);
            }
            return n;
        }));
        res.json(processed);
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

app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    console.log(`🗑️ DELETE /api/notifications/${id} requested for user: ${userId}`);

    // 1. Validate ID format to avoid cast errors
    if (!mongoose.Types.ObjectId.isValid(id)) {
        console.warn(`⚠️ Invalid Notification ID format: ${id}`);
        return res.status(400).json({ message: 'Invalid notification ID format' });
    }

    try {
        // 2. Find the notification
        const notification = await Notification.findById(id);

        if (!notification) {
            console.warn(`⚠️ Notification ${id} NOT FOUND.`);
            return res.status(404).json({ message: 'Notification not found' });
        }

        // 3. Authorization check
        const recipientId = notification.recipient.toString();
        if (recipientId !== userId) {
            console.warn(`🚫 User ${userId} tried to delete ${recipientId}'s notification.`);
            return res.status(403).json({ message: 'Not authorized to delete this notification' });
        }

        // 4. Perform deletion
        await Notification.findByIdAndDelete(id);

        console.log(`✅ Notification ${id} DELETED successfully.`);
        return res.json({ success: true, message: 'Notification deleted successfully' });

    } catch (err) {
        console.error(`🔥 ERROR in DELETE /api/notifications/${id}:`, err);
        return res.status(500).json({
            message: 'An error occurred while deleting the notification.',
            details: err.message
        });
    }
});

app.delete('/api/notifications', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    console.log(`🗑️ Clear all notifications requested for user: ${userId}`);
    try {
        const result = await Notification.deleteMany({ recipient: userId });
        console.log(`✅ Cleared ${result.deletedCount} notifications for user: ${userId}`);
        res.json({ success: true, message: 'All notifications cleared successfully', count: result.deletedCount });
    } catch (err) {
        console.error(`🔥 ERROR clearing notifications:`, err.message);
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
        }).sort({ createdAt: 1 }).lean();
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

        // Broadcast via Socket.io for real-time delivery
        const receiverSocketId = onlineUsers.get(receiverId);
        if (receiverSocketId) {
            io.to(receiverSocketId).emit('receive_message', {
                _id: message._id,
                content: message.content,
                sender: message.sender,
                receiver: message.receiver,
                messageType: message.messageType,
                createdAt: message.createdAt,
                isRead: message.isRead
            });
        }

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
        const userId = req.user.id;
        const me = await User.findById(userId).select('matches').lean();
        if (!me) {
            console.error('[Conversations] User not found:', userId);
            return res.status(404).json({ message: 'User not found' });
        }

        const matchIds = me.matches || [];
        if (matchIds.length === 0) return res.json([]);

        const matches = await User.find({ _id: { $in: matchIds } })
            .select('_id firstName lastName avatarUrl bio isOnline')
            .lean();

        const conversations = await Promise.all(matches.map(async (match) => {
            const matchIdStr = match._id ? match._id.toString() : null;
            if (!matchIdStr) {
                console.warn('[Conversations] Match missing _id:', match);
            }
            
            let lastMessage = null;
            try {
                lastMessage = await Message.findOne({
                    $or: [
                        { sender: userId, receiver: match._id },
                        { sender: match._id, receiver: userId }
                    ]
                }).sort({ createdAt: -1 }).lean();
            } catch (e) {
                console.error(`[Conversations] Error finding lastMessage:`, e);
            }

            const unreadCount = await Message.countDocuments({
                sender: match._id,
                receiver: userId,
                isRead: false
            });

            const signedMatch = await signUserMediaList(match);

            return {
                otherUser: signedMatch,
                lastMessage: lastMessage,
                unreadCount: unreadCount
            };
        }));

        res.json(conversations);
    } catch (err) {
        if (err.name === 'MongoNetworkTimeoutError' || err.message.includes('timeout')) {
            console.error('[Conversations] Timeout:', err.message);
            return res.status(504).json({ message: 'Database query timed out.' });
        }
        console.error('[Conversations] Error:', err.stack);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/messages/read/:otherUserId', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { otherUserId } = req.params;

        await Message.updateMany(
            { sender: otherUserId, receiver: userId, isRead: false },
            { $set: { isRead: true } }
        );

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// Status System
app.post('/api/status', authenticateToken, async (req, res) => {
    try {
        const { imageUrl, text } = req.body;
        if (!imageUrl) return res.status(400).json({ message: 'Image URL is required' });

        const status = new Status({
            user: req.user.id,
            imageUrl,
            text,
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
        console.log(`[StatusFeed] Fetching for user: ${req.user.id}`);
        const me = await User.findById(req.user.id).select('matches').lean();
        if (!me) {
            console.log(`[StatusFeed] User not found: ${req.user.id}`);
            return res.status(404).json({ message: 'User not found' });
        }

        // Include my own status and my matches' statuses
        const userIdsToFetch = [me._id, ...(me.matches || [])];

        const statuses = await Status.find({
            user: { $in: userIdsToFetch },
            expiresAt: { $gt: new Date() }
        })
            .populate('user', 'firstName lastName avatarUrl')
            .sort({ createdAt: -1 })
            .limit(20)
            .lean();

        const processed = await Promise.all(statuses.map(async (s) => {
            if (s.user) {
                s.user = await signUserMedia(s.user);
            }
            if (s.imageUrl) {
                s.imageUrl = await signUrl(s.imageUrl);
            }
            return s;
        }));

        console.log(`[StatusFeed] Found ${processed.length} statuses`);
        res.json(processed);
    } catch (err) {
        if (err.name === 'MongoNetworkTimeoutError' || err.message.includes('timeout')) {
            console.error('[StatusFeed] Timeout:', err.message);
            return res.status(504).json({ message: 'Database query timed out. Please try again.' });
        }
        console.error('[StatusFeed] Error:', err.stack);
        res.status(500).json({ message: 'Server error: ' + err.message });
    }
});


// Event System
app.get('/api/events', authenticateToken, async (req, res) => {
    try {
        // List view should be fast: don't populate/sign every attendee.
        // Details endpoint (/api/events/:id) still returns full attendee objects.
        const events = await Event.find()
            .populate('createdBy', 'firstName lastName avatarUrl')
            .sort({ date: 1 })
            .lean();

        const processed = await Promise.all(events.map(async (e) => {
            const data = e || {};
            if (data.createdBy) data.createdBy = await signUserMedia(data.createdBy);
            if (data.imageUrl) data.imageUrl = await signUrl(data.imageUrl);
            // Leave attendees as ids (or array) so length/count still works client-side,
            // but avoid populating + signing them here.
            return data;
        }));

        res.json(processed);
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

        const data = event.toObject ? event.toObject() : event;
        if (data.createdBy) data.createdBy = await signUserMedia(data.createdBy);
        if (data.attendees) data.attendees = await Promise.all(data.attendees.map(a => signUserMedia(a)));
        if (data.imageUrl) data.imageUrl = await signUrl(data.imageUrl);
        res.json(data);
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

// Final Health Check & Status Route
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
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
server.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});

module.exports = app;
