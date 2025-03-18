import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import passport from 'passport';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import userRoutes from './routes/user.route.js';
import authRoutes from './routes/auth.route.js';
import postRoutes from './routes/post.route.js';
import commentRoutes from './routes/comment.route.js';
import { errorHandler } from './utils/errorHandler.js'; // Penanganan kesalahan
import './middlewares/passport.js'; // Konfigurasi Passport


// ✅ Load Environment Variables
dotenv.config();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO;
const JWT_SECRET = process.env.JWT_SECRET;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

// ✅ Pastikan semua variabel environment tersedia
if (!MONGO_URI) {
  console.error("❌ ERROR: Variabel MONGO belum dikonfigurasi di .env");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ ERROR: Variabel JWT_SECRET belum dikonfigurasi di .env");
  process.exit(1);
}

// ✅ Pastikan __dirname bekerja dengan ES Module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ✅ Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: CLIENT_URL,
  credentials: true,
}));

// ✅ MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log("✅ MongoDB Connected");
  } catch (error) {
    console.error("❌ MongoDB Connection Error:", error);
  }
};

// 🔄 MongoDB Connection Events
mongoose.connection.on("connected", () => console.log("✅ MongoDB is connected"));
mongoose.connection.on("error", (err) => console.error("❌ MongoDB Error:", err));
mongoose.connection.on("disconnected", () => console.warn("⚠️ MongoDB disconnected"));

// ✅ API Routes
app.use('/api/user', userRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/post', postRoutes);
app.use('/api/comment', commentRoutes);

app.use(session({
  secret: process.env.SESSION_SECRET || "your_secret_key", // Ganti dengan yang lebih aman
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false, // Gunakan true jika HTTPS
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24, // 1 hari
  }
}));

app.use(passport.initialize());
app.use(passport.session());


// ✅ Serve Static Files for Production
const clientPath = path.join(__dirname, '../client/dist');
if (fs.existsSync(clientPath)) {
  app.use(express.static(clientPath));

  // ✅ Redirect all unknown routes to index.html (Frontend SPA)
  app.get('*', (req, res) => {
    res.sendFile(path.join(clientPath, 'index.html'));
  });
} else {
  console.warn("⚠️ WARNING: Folder 'client/dist' tidak ditemukan. Pastikan frontend sudah di-build.");
}

// ✅ Global Error Handler
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  console.error(`🔥 Error: ${message}`);
  res.status(statusCode).json({
    success: false,
    statusCode,
    message,
  });
});

// ✅ Start Server setelah koneksi MongoDB berhasil
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
  });
});

