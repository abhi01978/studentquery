require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const { v2: cloudinary } = require("cloudinary");

// -------------------------------
// CLOUDINARY CONFIG
// -------------------------------
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// -------------------------------
// BASIC CONFIG
// -------------------------------
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret_to_strong_one";
const app = express();

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: "*", credentials: true }));
app.use(express.static(path.join(__dirname, "public")));

// -------------------------------
// JWT VERIFY MIDDLEWARE
// -------------------------------
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token, login kar bhai!" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token!" });
  }
};

// -------------------------------
// MONGODB CONNECT
// -------------------------------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log("Mongo Error:", err));

// -------------------------------
// USER & NOTE MODELS
// -------------------------------
// USER MODEL (Yeh pura replace kar de)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  board: { type: String, enum: ["CBSE", "UP Board", "ICSE", "State Board", "Other"], required: true },
  university: String,
  college: String,
  course: String,
  semester: String,
  dream: String,
  profileImg: { type: String, default: null },
  category: { type: String, enum: ["School", "UG", "PG", "Other"], default: "Other" },
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", default: [] }]
}, { timestamps: true });

const noteSchema = new mongoose.Schema({
  title: { type: String, required: true },
  subject: { type: String, required: true },
  fileUrl: { type: String, required: true },
  uploader: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  uploaderName: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Note = mongoose.model("Note", noteSchema);

// -------------------------------
// 2 ALAG MULTER MIDDLEWARES
// -------------------------------
const storage = multer.memoryStorage();

// 1. Sirf Images (Profile Pic)
const uploadImage = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp/;
    const ext = allowed.test(path.extname(file.originalname).toLowerCase());
    const mime = allowed.test(file.mimetype);
    if (ext && mime) cb(null, true);
    else cb(new Error("Only images allowed (jpeg, jpg, png, webp)"));
  }
});

// 2. Sirf PDF (Notes Upload)
const uploadPDF = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB PDF
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") {
      cb(null, true);
    } else {
      cb(new Error("Only PDF files allowed!"));
    }
  }
});

// -------------------------------
// CLOUDINARY UPLOAD HELPERS
// -------------------------------
const uploadImageToCloudinary = (buffer) => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader.upload_stream(
      { folder: "studentquery/profiles", resource_type: "image" },
      (error, result) => error ? reject(error) : resolve(result.secure_url)
    ).end(buffer);
  });
};

const uploadPDFToCloudinary = (buffer, originalName) => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader.upload_stream(
      {
        folder: "studentquery/notes",
        resource_type: "raw",
        public_id: Date.now() + "_" + originalName.replace(/\s+/g, "_"),
      },
      (error, result) => error ? reject(error) : resolve(result.secure_url)
    ).end(buffer);
  });
};

// -------------------------------
// ROUTES
// -------------------------------
app.post("/api/auth/signup", uploadImage.single("profileImg"), async (req, res) => {
  try {
    const { name, phone, password, board, university, college, course, semester, dream, category } = req.body;
    if (!name || !phone || !password || !board) return res.status(400).json({ message: "Required fields missing" });

    if (await User.findOne({ phone })) return res.status(400).json({ message: "Phone already registered" });

    const hashed = await bcrypt.hash(password, 10);
    let profileImgUrl = null;
    if (req.file) profileImgUrl = await uploadImageToCloudinary(req.file.buffer);

    const user = await User.create({
      name, phone, password: hashed, board, university, college, course, semester, dream,
      category: category || "Other", profileImg: profileImgUrl
    });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    const safeUser = user.toObject(); delete safeUser.password;
    res.json({ message: "Signup success", user: safeUser, token });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await User.findOne({ phone });
    if (!user || !await bcrypt.compare(password, user.password))
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    const safe = user.toObject(); delete safe.password;
    res.json({ message: "Login success", user: safe, token });
  } catch (err) {
    res.status(500).json({ message: "Error" });
  }
});

// /api/me route (Yeh replace kar de)
app.get("/api/me", async (req, res) => {
  try {
    let token = req.headers.authorization;
    if (!token) return res.status(401).json({ message: "No token" });
    if (token.startsWith("Bearer ")) token = token.slice(7);

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");

    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ user });
  } catch (err) {
    console.log("Token error:", err);
    res.status(401).json({ message: "Invalid token" });
  }
});

// -------------------------------
// NOTES ROUTES (PDF UPLOAD FIXED)
// -------------------------------
app.get("/api/notes", async (req, res) => {
  const notes = await Note.find().sort({ createdAt: -1 });
  res.json({ notes });
});


app.post("/api/notes", verifyToken, uploadPDF.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "PDF file required!" });

    const { title, subject } = req.body;
    if (!title || !subject) return res.status(400).json({ message: "Title & subject required!" });

    const fileUrl = await uploadPDFToCloudinary(req.file.buffer, req.file.originalname);

    const note = new Note({
      title,
      subject,
      fileUrl,
      uploader: req.user.id,
      uploaderName: req.user.name || "Student"
    });

    await note.save();
    res.json({ message: "PDF Uploaded Successfully!", note });
  } catch (err) {
    console.log("PDF Upload Error:", err);
    res.status(500).json({ message: "Upload failed", error: err.message });
  }
});

// -------------------------------
// SERVE FRONTEND
// -------------------------------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/profile", (req, res) => res.sendFile(path.join(__dirname, "public", "profile.html")));
app.get("/notes.html", (req, res) => res.sendFile(path.join(__dirname, "public", "notes.html")));
app.get("/new.html", (req, res) => res.sendFile(path.join(__dirname, "public", "new.html")));



// YE 2 NAYE ROUTES ADD KAR DE
app.get("/following.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "following.html"));
});

app.get("/userprofile.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "userprofile.html"));
});

// 1. Saare users fetch karne ke liye (classmates ke liye)
// FIXED ROUTE — Ab Followers bhi 100% kaam karega!
app.get("/api/users", verifyToken, async (req, res) => {
  try {
    const users = await User.find()
      .select("name profileImg _id course semester board following") // ← YE LINE ADD KI!
      .lean();

    res.json({ users });
  } catch (err) {
    console.log("Error in /api/users:", err);
    res.status(500).json({ message: "Error fetching users" });
  }
});
// 2. Follow / Unfollow (simple array based - baad mein advanced kar dena)
app.post("/api/follow/:userId", verifyToken, async (req, res) => {
  try {
    const targetUserId = req.params.userId;
    const currentUser = await User.findById(req.user.id);

    if (!currentUser.following) currentUser.following = [];

    const index = currentUser.following.indexOf(targetUserId);
    if (index === -1) {
      currentUser.following.push(targetUserId);
    } else {
      currentUser.following.splice(index, 1);
    }
    await currentUser.save();

    res.json({ following: currentUser.following.includes(targetUserId) });
  } catch (err) {
    res.status(500).json({ message: "Follow error" });
  }
});
// -------------------------------
// START SERVER
// -------------------------------
app.listen(PORT, () => {
  console.log(`Server running on https://studentquery.onrender.com`);
  console.log(`Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME}`);
});






