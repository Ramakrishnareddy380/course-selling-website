require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const mongoose = require("mongoose");

// Environment Variables
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error("Error: Missing environment variables.");
  process.exit(1);
}

// Initialize Express App
const app = express();
app.use(bodyParser.json());
app.use(cors());

// Database Connection
mongoose
  .connect(MONGODB_URI, {
    dbName: DB_NAME,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ Database Connected Successfully"))
  .catch((err) => {
    console.error("❌ Database Connection Error:", err);
    process.exit(1);
  });

// Mongoose Schemas & Models
const Schema = mongoose.Schema;

const adminSchema = new Schema({
  username: String,
  password: String,
});

const userSchema = new Schema({
  username: String,
  password: String,
  purchasedCourses: [{ type: Schema.Types.ObjectId, ref: "Course" }],
});

const courseSchema = new Schema({
  title: String,
  description: String,
  price: Number,
  imageLink: String,
  published: { type: Boolean, default: true },
  createdBy: { type: Schema.Types.ObjectId, ref: "Admin" },
});

const Admin = mongoose.model("Admin", adminSchema);
const User = mongoose.model("User", userSchema);
const Course = mongoose.model("Course", courseSchema);

// Middleware for Authentication
function isAuthenticated(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Missing Authorization Header" });
  }
  
  const token = authHeader.split(" ")[1];
  
  jwt.verify(token, JWT_SECRET, (err, data) => {
    if (err) {
      return res.status(403).json({ message: "Unauthorized Access" });
    }
    req.user = data;
    next();
  });
}

function isAdmin(req, res, next) {
  if (req.user.role !== "Admin") {
    return res.status(403).json({ message: "Admins Only Allowed" });
  }
  next();
}

// Admin Routes
app.post("/admin/signup", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required." });
  }

  let admin = await Admin.findOne({ username });
  if (admin) {
    return res.status(409).json({ message: "Admin already exists." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  admin = await Admin.create({ username, password: hashedPassword });

  const token = jwt.sign({ username, role: "Admin" }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ message: "Admin created successfully", token });
});

app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required." });
  }

  let admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password, admin.password))) {
    return res.status(401).json({ message: "Invalid credentials." });
  }

  const token = jwt.sign({ username, role: "Admin" }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ message: "Admin logged in successfully", token });
});

app.post("/admin/courses", isAuthenticated, isAdmin, async (req, res) => {
  const { title, description, imageLink, price } = req.body;

  if (!title || !description || !imageLink || !price) {
    return res.status(400).json({ message: "Incomplete course details." });
  }

  const admin = await Admin.findOne({ username: req.user.username });
  if (!admin) {
    return res.status(404).json({ message: "Admin not found." });
  }

  const course = await Course.create({
    ...req.body,
    createdBy: admin._id,
  });

  res.json({ message: "Course created successfully", course });
});

// User Routes
app.post("/users/signup", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required." });
  }

  let user = await User.findOne({ username });
  if (user) {
    return res.status(409).json({ message: "User already exists." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  user = await User.create({ username, password: hashedPassword });

  const token = jwt.sign({ username, role: "User" }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ message: "User created successfully", token });
});

app.post("/users/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required." });
  }

  let user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid credentials." });
  }

  const token = jwt.sign({ username, role: "User" }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ message: "User logged in successfully", token });
});

app.get("/users/courses", isAuthenticated, async (req, res) => {
  const courses = await Course.find({ published: true }).populate("createdBy");
  res.json({ courses });
});

app.post("/users/courses/:id", isAuthenticated, async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid Course ID." });
  }

  const course = await Course.findById(id);
  if (!course) {
    return res.status(404).json({ message: "Course not found." });
  }

  const user = await User.findOne({ username: req.user.username });
  if (!user) {
    return res.status(404).json({ message: "User not found." });
  }

  if (user.purchasedCourses.includes(id)) {
    return res.status(409).json({ message: "Course already purchased." });
  }

  user.purchasedCourses.push(course);
  await user.save();

  res.json({ message: "Course purchased successfully." });
});

app.get("/users/purchasedCourses", isAuthenticated, async (req, res) => {
  const user = await User.findOne({ username: req.user.username }).populate("purchasedCourses");
  if (!user) {
    return res.status(404).json({ message: "User not found." });
  }
  res.json({ purchasedCourses: user.purchasedCourses });
});

module.exports = app;
// Server Start
// app.listen(PORT, () => {
//   console.log(`🚀 Server running on port ${PORT}`);
// });
