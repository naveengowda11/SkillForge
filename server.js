require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const nodemailer = require("nodemailer");

const app = express();

app.use(cors());
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const SECRET_KEY = process.env.JWT_SECRET;

// ================= DATABASE =================

const db = new sqlite3.Database("./database.db");

db.run(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  password TEXT
)
`);

// ================= OTP STORE =================

const otpStore = {};

// ================= EMAIL SETUP =================

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

// ================= REGISTER =================

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
    [name, email, hashedPassword],
    function (err) {
      if (err) {
        return res.status(400).json({ message: "User already exists" });
      }
      res.json({ message: "Registration successful" });
    }
  );
});

// ================= LOGIN =================

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id }, SECRET_KEY, {
      expiresIn: "1h",
    });

    res.json({
      token,
      name: user.name,
      email: user.email
    });
  });
});

// ================= GOOGLE OAUTH =================

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:5000/auth/google/callback"
  },
  (accessToken, refreshToken, profile, done) => {

    const email = profile.emails[0].value;
    const name = profile.displayName;

    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {

      if (user) {
        return done(null, user);
      }

      db.run(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        [name, email, "google_oauth"],
        function () {
          db.get("SELECT * FROM users WHERE email = ?", [email], (err, newUser) => {
            return done(null, newUser);
          });
        }
      );
    });
  }
));

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {

    const token = jwt.sign({ id: req.user.id }, SECRET_KEY, {
      expiresIn: "1h",
    });

    res.redirect(
      `${process.env.FRONTEND_URL}/dashboard.html?token=${token}&name=${encodeURIComponent(req.user.name)}&email=${encodeURIComponent(req.user.email)}`
    );
  }
);

// ================= SEND OTP =================

app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;

  const otp = Math.floor(100000 + Math.random() * 900000);

  otpStore[email] = otp;

  try {
    await transporter.sendMail({
      from: "SkillForge",
      to: email,
      subject: "SkillForge OTP Verification",
      text: `Your OTP is: ${otp}`
    });

    res.json({ message: "OTP sent successfully" });

  } catch (error) {
    res.status(500).json({ message: "Failed to send OTP" });
  }
});
app.post("/api/forgot-password/send-otp", (req, res) => {
  const { email } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (!user) {
      return res.status(400).json({ message: "Email not registered" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000);
    resetOtpStore[email] = otp;

    try {
      await transporter.sendMail({
        from: "SkillForge",
        to: email,
        subject: "Password Reset OTP",
        text: `Your password reset OTP is: ${otp}`
      });

      res.json({ message: "OTP sent successfully" });

    } catch (error) {
      res.status(500).json({ message: "Failed to send OTP" });
    }
  });
});
// ================= VERIFY OTP =================

app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (otpStore[email] == otp) {
    delete otpStore[email];
    res.json({ verified: true });
  } else {
    res.status(400).json({ message: "Invalid OTP" });
  }
});
app.post("/api/forgot-password/reset", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (resetOtpStore[email] != otp) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  db.run(
    "UPDATE users SET password = ? WHERE email = ?",
    [hashedPassword, email],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Error updating password" });
      }

      delete resetOtpStore[email];

      db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });

        res.json({
          message: "Password reset successful",
          token,
          name: user.name,
          email: user.email
        });
      });
    }
  );
});

// ================= SERVER =================

app.listen(process.env.PORT, () => {
  console.log(`Server running on http://localhost:${process.env.PORT}`);
});