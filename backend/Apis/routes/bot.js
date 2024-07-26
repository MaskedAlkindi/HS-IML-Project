const express = require("express");
const mysql = require("mysql2/promise");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const fs = require("fs");

dotenv.config();

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

const botRouter = express.Router();

const authenticatePasskey = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const passkey = authHeader && authHeader.split(' ')[1];

  if (!passkey) return res.sendStatus(401);

  const [rows] = await db.execute("SELECT * FROM Bots WHERE Passkey = ?", [passkey]);
  const bot = rows[0];

  if (!bot) return res.sendStatus(403);

  req.bot = bot;
  next();
};

botRouter.get("/logs", authenticatePasskey, async (req, res) => {
  const { bot } = req;

  try {
    const [rows] = await db.execute("SELECT * FROM Logs WHERE Username = ?", [bot.Username]);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Error retrieving logs", error: error.message });
  }
});

botRouter.get("/getallbots", async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT BotToken FROM Bots WHERE IsActive = 1");
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Error retrieving bots", error: error.message });
  }
});

botRouter.get("/test-db", async (req, res) => {
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

module.exports = botRouter;
