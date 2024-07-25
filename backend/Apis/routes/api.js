const express = require("express");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const fs = require("fs");

dotenv.config();

const app = express();
app.use(bodyParser.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    ca: fs.readFileSync("./certificates/ca-certificate.crt"),
  },
});

const router = express.Router();

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const createLog = async (action, details, username) => {
  await db.execute("INSERT INTO Logs (Action, Details, Username) VALUES (?, ?, ?)", 
    [action, details, username]);
};

router.get("/", async (req, res, next) => {
  return res.status(200).json({
    title: "Express Testing",
    message: "The app is working properly!",
  });
});


// Signup Endpoint
router.post("/signup", async (req, res) => {
  const { username, firstName, lastName, password} = req.body;

  if (!username || !firstName || !lastName || !password || !type) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  try {
    await db.execute("INSERT INTO Users (Username, FirstName, LastName, HashedPassword, Type) VALUES (?, ?, ?, ?, ?)", 
      [username, firstName, lastName, hashedPassword, "normal user"]);
    await createLog("signup", "User signed up", username);
    const token = jwt.sign({ username: user.Username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
   
  } catch (error) {
    res.status(500).json({ message: "Error creating user", error: error.message });
  }
});

// Login Endpoint
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await db.execute("SELECT * FROM Users WHERE Username = ?", [username]);
  const user = rows[0];

  if (user && bcrypt.compareSync(password, user.HashedPassword)) {
    const token = jwt.sign({ username: user.Username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await createLog("login", "User logged in", username);
    res.json({ token });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

router.post("/createscan", authenticateToken, async (req, res) => {
  const { file_info, ismalware } = req.body;
  const { username } = req.user;

  await db.execute("INSERT INTO Scans (File_info, IsMalware, Username) VALUES (?, ?, ?)", 
    [JSON.stringify(file_info), ismalware, username]);
  await createLog("create scan", "User created a scan", username);

  res.status(201).json({ message: "Scan created successfully" });
});

router.get("/getallscans", authenticateToken, async (req, res) => {
  const { username } = req.user;

  const [rows] = await db.execute("SELECT * FROM Scans WHERE Username = ?", [username]);
  
  const today = new Date();
  const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
  const monthAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);
  const yearAgo = new Date(today.getTime() - 365 * 24 * 60 * 60 * 1000);

  const todayScans = rows.filter(scan => new Date(scan.TimeStamp) >= today.setHours(0, 0, 0, 0));
  const weekScans = rows.filter(scan => new Date(scan.TimeStamp) >= weekAgo);
  const monthScans = rows.filter(scan => new Date(scan.TimeStamp) >= monthAgo);
  const yearScans = rows.filter(scan => new Date(scan.TimeStamp) >= yearAgo);

  await createLog("get all scans", "User retrieved all scans", username);

  res.json({
    allScans: rows,
    todayScans,
    weekScans,
    monthScans,
    yearScans,
  });
});

router.get("/logs", authenticateToken, async (req, res) => {
  const { username } = req.user;

  const [rows] = await db.execute("SELECT * FROM Logs WHERE Username = ?", [username]);
  
  res.json(rows);
});

router.get("/test-db", async (req, res) => {
  try {
    await db.query("SELECT 1");
    res.status(200).json({
      message: "Database connection successful!"
    });
  } catch (error) {
    res.status(500).json({
      message: "Database connection failed",
      error: error.message
    });
  }
});


module.exports = router;
