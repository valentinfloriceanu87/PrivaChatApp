const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── MongoDB connection ──────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => { console.error('MongoDB connection failed:', err.message); process.exit(1); });

// ── Schemas ─────────────────────────────────────────────────────────────────
const User = mongoose.model('User', new mongoose.Schema({
  username:     { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
}));

const Message = mongoose.model('Message', new mongoose.Schema({
  from:            { type: String, required: true },
  to:              { type: String, required: true },
  conversationKey: { type: String, required: true, index: true },
  text:            { type: String, required: true },
  timestamp:       { type: Date, default: Date.now },
}));

// Sessions stay in memory — users re-login after a restart, but accounts persist
const sessions = new Map(); // token -> username

// ── Helpers ──────────────────────────────────────────────────────────────────
function conversationKey(a, b) { return [a, b].sort().join('::'); }

function fmtMsg(m) {
  return {
    id:        m._id.toString(),
    from:      m.from,
    to:        m.to,
    text:      m.text,
    timestamp: m.timestamp instanceof Date ? m.timestamp.toISOString() : m.timestamp,
  };
}

// ── REST: Register ───────────────────────────────────────────────────────────
app.post('/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required.' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.status(400).json({ error: 'Username must be 3-20 alphanumeric characters.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    await User.create({ username, passwordHash });
    res.json({ success: true });
  } catch (err) {
    if (err.code === 11000)
      return res.status(409).json({ error: 'Username already taken.' });
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── REST: Login ──────────────────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required.' });

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials.' });

    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, username);
    res.json({ token, username });
  } catch {
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Socket.io auth middleware ────────────────────────────────────────────────
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const username = sessions.get(token);
  if (!username) return next(new Error('Unauthorized'));
  socket.username = username;
  next();
});

// ── Socket.io events ─────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  const me = socket.username;
  socket.join(`user:${me}`);

  // Conversations list for the sidebar
  socket.on('get_conversations', async (cb) => {
    try {
      const results = await Message.aggregate([
        { $match: { $or: [{ from: me }, { to: me }] } },
        { $sort:  { timestamp: -1 } },
        { $group: { _id: '$conversationKey', lastMessage: { $first: '$$ROOT' } } },
        { $sort:  { 'lastMessage.timestamp': -1 } },
      ]);

      cb(results.map(r => ({
        with:        r._id.split('::').find(u => u !== me),
        lastMessage: {
          id:        r.lastMessage._id.toString(),
          from:      r.lastMessage.from,
          to:        r.lastMessage.to,
          text:      r.lastMessage.text,
          timestamp: r.lastMessage.timestamp instanceof Date
                       ? r.lastMessage.timestamp.toISOString()
                       : r.lastMessage.timestamp,
        },
      })));
    } catch { cb([]); }
  });

  // Full message history with one user
  socket.on('get_messages', async ({ with: target }, cb) => {
    try {
      const exists = await User.exists({ username: target });
      if (!exists) return cb({ error: 'User not found.' });
      const msgs = await Message
        .find({ conversationKey: conversationKey(me, target) })
        .sort({ timestamp: 1 })
        .lean();
      cb(msgs.map(fmtMsg));
    } catch { cb([]); }
  });

  // Check if a username exists
  socket.on('check_user', async (target, cb) => {
    try {
      cb(!!(await User.exists({ username: target })));
    } catch { cb(false); }
  });

  // Send a private message
  socket.on('private_message', async ({ to, text }, cb) => {
    try {
      const exists = await User.exists({ username: to });
      if (!exists)          return cb && cb({ error: 'User not found.' });
      if (to === me)        return cb && cb({ error: 'You cannot message yourself.' });
      if (!text?.trim())    return cb && cb({ error: 'Message cannot be empty.' });
      if (text.length > 2000) return cb && cb({ error: 'Message too long (max 2000 chars).' });

      const saved = await Message.create({
        from: me, to,
        conversationKey: conversationKey(me, to),
        text: text.trim(),
        timestamp: new Date(),
      });

      const message = fmtMsg(saved);
      io.to(`user:${to}`).emit('new_message', message);
      cb && cb({ success: true, message });
    } catch {
      cb && cb({ error: 'Failed to send message.' });
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`PrivateChat running → http://localhost:${PORT}`);
});
