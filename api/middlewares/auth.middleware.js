import jwt from "jsonwebtoken";
import { errorHandler } from "../utils/errorHandler.js";

export const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized! No token provided." });
  }

  const token = authHeader.split(" ")[1]; // ✅ Ambil token setelah "Bearer"

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("🔴 Token verification failed:", err.message);
      return res.status(403).json({ message: "Forbidden! Invalid token." });
    }

    req.user = decoded; // ✅ Simpan user ID dan role ke `req.user`
    console.log("🔐 Authenticated User:", req.user);
    next();
  });
};



export const verifyAdmin = (req, res, next) => {
  console.log("🛂 Middleware Admin Check:", req.user);

  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      statusCode: 403,
      message: "You are not allowed to see all users",
    });
  }

  next();
};
