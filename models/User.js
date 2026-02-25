const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: false // Optional initially during OTP phase
    },
    otp: {
        type: String,
        required: false
    },
    otpExpires: {
        type: Date,
        required: false
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    // Profile Fields
    firstName: String,
    lastName: String,
    username: String,
    gender: String,
    dateOfBirth: Date,
    city: String,
    country: String,
    relationshipStatus: String,
    bio: String,
    avatarUrl: String, // Primary Photo
    secondaryPhotoUrl: String,
    thirdPhotoUrl: String,
    videoUrl: String,
    interests: [String],

    // Onboarding & Preferences
    onboardingStatus: {
        type: String,
        enum: ['started', 'profile_created', 'interests_selected', 'preferences_set', 'media_uploaded', 'completed'],
        default: 'started'
    },
    preferences: {
        lookingForGender: String,
        lookingForRelationshipStatus: String,
        distanceKm: { type: Number, default: 50 },
        ageMin: { type: Number, default: 18 },
        ageMax: { type: Number, default: 40 },
        heightMinCm: Number,
        heightMaxCm: Number
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastPasswordReset: {
        type: Date,
        required: false
    },
    likedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    matches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    isOnline: { type: Boolean, default: false },
    lastActive: { type: Date, default: Date.now },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },

    // OTP Rate Limiting
    otpCount: { type: Number, default: 0 },
    lastOtpSent: { type: Date },
    resetOtpCount: { type: Number, default: 0 },
    lastResetOtpSent: { type: Date }
});

// Indexes for performance

userSchema.index({ onboardingStatus: 1 });
userSchema.index({ likedUsers: 1 });
userSchema.index({ matches: 1 });

// Hash password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    console.log(`🔐 Hashing password for user: ${this.email}`);
    try {
        this.password = await bcrypt.hash(this.password, 10);
        console.log(`✅ Password hashed successfully`);
        next();
    } catch (err) {
        console.error('❌ Error hashing password:', err);
        next(err);
    }
});

// Method to compare password
userSchema.methods.comparePassword = async function (candidatePassword) {
    if (!this.password) {
        console.warn(`⚠️ comparePassword: No password set for user: ${this.email}`);
        return false;
    }
    const match = await bcrypt.compare(candidatePassword, this.password);
    console.log(`🔍 Password comparison for ${this.email}: ${match ? 'MATCH' : 'MISMATCH'}`);
    return match;
};

module.exports = mongoose.model('User', userSchema);
