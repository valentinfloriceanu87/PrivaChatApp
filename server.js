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

// ── MongoDB connection ───────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => { console.log('MongoDB connected'); cleanupOldMessages(); })
  .catch(err => { console.error('MongoDB connection failed:', err.message); process.exit(1); });

// ── Schemas ──────────────────────────────────────────────────────────────────
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
  read:            { type: Boolean, default: false },
  readAt:          { type: Date, default: null },
}));

// Sessions stay in memory
const sessions = new Map();

// ── Auto-cleanup ─────────────────────────────────────────────────────────────
// Delete messages that have been READ and are older than 10 days.
// Unread messages are never auto-deleted.
async function cleanupOldMessages() {
  const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
  try {
    const result = await Message.deleteMany({
      read: true,
      timestamp: { $lt: tenDaysAgo },
    });
    if (result.deletedCount > 0)
      console.log(`Cleanup: removed ${result.deletedCount} old read messages`);
  } catch (err) {
    console.error('Cleanup error:', err);
  }
}
setInterval(cleanupOldMessages, 60 * 60 * 1000); // every hour

// ── Helpers ───────────────────────────────────────────────────────────────────
function conversationKey(a, b) { return [a, b].sort().join('::'); }

function fmtMsg(m) {
  return {
    id:        m._id.toString(),
    from:      m.from,
    to:        m.to,
    text:      m.text,
    timestamp: m.timestamp instanceof Date ? m.timestamp.toISOString() : m.timestamp,
    read:      m.read,
  };
}

// ── REST: Register ────────────────────────────────────────────────────────────
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

// ── REST: Login ───────────────────────────────────────────────────────────────
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

// ── Socket.io auth ────────────────────────────────────────────────────────────
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const username = sessions.get(token);
  if (!username) return next(new Error('Unauthorized'));
  socket.username = username;
  next();
});

// ── Socket.io events ──────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  const me = socket.username;
  socket.join(`user:${me}`);

  // Conversations list with unread counts
  socket.on('get_conversations', async (cb) => {
    try {
      const results = await Message.aggregate([
        { $match: { $or: [{ from: me }, { to: me }] } },
        { $sort: { timestamp: -1 } },
        { $group: {
          _id: '$conversationKey',
          lastMessage: { $first: '$$ROOT' },
          unreadCount: {
            $sum: {
              $cond: [
                { $and: [{ $eq: ['$to', me] }, { $eq: ['$read', false] }] },
                1, 0
              ]
            }
          }
        }},
        { $sort: { 'lastMessage.timestamp': -1 } },
      ]);
      cb(results.map(r => ({
        with:        r._id.split('::').find(u => u !== me),
        lastMessage: fmtMsg(r.lastMessage),
        unreadCount: r.unreadCount,
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

  // Mark all messages in a conversation as read
  socket.on('mark_read', async ({ with: target }, cb) => {
    try {
      const key = conversationKey(me, target);
      const result = await Message.updateMany(
        { conversationKey: key, to: me, read: false },
        { read: true, readAt: new Date() }
      );
      if (result.modifiedCount > 0) {
        // Tell the sender their messages were read
        io.to(`user:${target}`).emit('messages_read', { by: me });
      }
      cb && cb({ success: true });
    } catch { cb && cb({ error: 'Failed.' }); }
  });

  // Delete a message — sender only, disappears for both parties
  socket.on('delete_message', async ({ messageId }, cb) => {
    try {
      const msg = await Message.findById(messageId);
      if (!msg)          return cb && cb({ error: 'Message not found.' });
      if (msg.from !== me) return cb && cb({ error: 'Not authorized.' });
      await Message.findByIdAndDelete(messageId);
      io.to(`user:${msg.to}`).emit('message_deleted', { messageId });
      socket.emit('message_deleted', { messageId });
      cb && cb({ success: true });
    } catch { cb && cb({ error: 'Failed to delete.' }); }
  });

  // Check if a username exists
  socket.on('check_user', async (target, cb) => {
    try { cb(!!(await User.exists({ username: target }))); }
    catch { cb(false); }
  });

  // Send a private message
  socket.on('private_message', async ({ to, text }, cb) => {
    try {
      const exists = await User.exists({ username: to });
      if (!exists)           return cb && cb({ error: 'User not found.' });
      if (to === me)         return cb && cb({ error: 'You cannot message yourself.' });
      if (!text?.trim())     return cb && cb({ error: 'Message cannot be empty.' });
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
