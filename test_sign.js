
const mongoose = require('mongoose');
const { GetObjectCommand, S3Client } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
require('dotenv').config();

const r2Client = new S3Client({
    region: 'auto',
    endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: {
        accessKeyId: process.env.CLOUDFLARE_ACCESS_KEY_ID,
        secretAccessKey: process.env.CLOUDFLARE_SECRET_ACCESS_KEY,
    },
});

async function signUserVideos(userObj) {
    if (!userObj) return userObj;
    const data = userObj.toObject ? userObj.toObject() : userObj;

    if (!data.videoUrl) {
        return data;
    }

    console.log(`[Sign] Processing video: ${data.videoUrl}`);

    const isR2 = data.videoUrl.includes('r2.cloudflarestorage.com') ||
        data.videoUrl.includes('pub-') ||
        data.videoUrl.includes('.r2.dev');

    if (isR2) {
        try {
            const url = new URL(data.videoUrl);
            const rawKey = url.pathname.startsWith('/') ? url.pathname.substring(1) : url.pathname;

            let decodedKey = rawKey;
            for (let i = 0; i < 3; i++) {
                try {
                    const next = decodeURIComponent(decodedKey);
                    if (next === decodedKey) break;
                    decodedKey = next;
                } catch (e) { break; }
            }

            console.log(`[Sign] Extracted Key: "${decodedKey}"`);

            const command = new GetObjectCommand({
                Bucket: process.env.CLOUDFLARE_BUCKET_NAME,
                Key: decodedKey
            });

            const signedUrl = await getSignedUrl(r2Client, command, { expiresIn: 3600 });
            console.log(`[Sign] SUCCESS. Signed URL: ${signedUrl.substring(0, 100)}...`);
            return { ...data, videoUrl: signedUrl };
        } catch (e) {
            console.error(`[Sign] FAILED:`, e.message);
            return data;
        }
    }
    return data;
}

async function run() {
    const testUser = {
        firstName: 'Andi',
        videoUrl: "https://pub-4fbb4303221540d9822de46cdd4b039d.r2.dev/uploads/69a84b4091a346b98ca09653/1772637260675-491408.mp4"
    };

    const result = await signUserVideos(testUser);
    console.log('Result:', JSON.stringify(result, null, 2));
}

run();
