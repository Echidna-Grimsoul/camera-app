require('dotenv').config();
const express = require('express');
const app = express();

// ─── AUTH IMPORTS ────────────────────────────────────────────────────────
const db = require('./models/db');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');

// ─── USER AUTH ROUTES ───────────────────────────────────────────────────

// 1) Signup
app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).send('Hashing error');
    db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hash],
      err => {
        if (err) return res.status(400).send('Username taken');
        res.send('Signed up');
      }
    );
  });
});

// 2) Login
app.post(
  '/login',
  passport.authenticate('local'),
  (req, res) => res.send('Logged in')
);

// 3) Logout
app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.send('Logged out');
  });
});

// ─── PASSPORT STRATEGY & SESSION SETUP ─────────────────────────────────
passport.use(new LocalStrategy((username, password, done) => {
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return done(err);
    if (!user) return done(null, false);
    bcrypt.compare(password, user.password, (e, res) => {
      if (res) return done(null, user);
      return done(null, false);
    });
  });
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, user) => done(err, user));
});

app.use(require('express-session')({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

app.use(express.json());
app.use(express.static('public'));

const server = require('http').createServer(app);
const io = require('socket.io')(server);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server on ${PORT}`));
