const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const cors = require('cors');

require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const API_URL = process.env.API_URL;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

async function startServer() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  console.log('Connected to MongoDB Atlas');

  const db = client.db('Shareoh');
  const usersCol = db.collection('users');
  const itemsCol = db.collection('items');

  // Middleware to protect routes
const jwt = require('jsonwebtoken');

const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];  // Extract token from Bearer

  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);  // Replace with your JWT secret
    req.userId = decoded.id;  // Store the userId from decoded token
    next();  // Proceed to the next middleware/route
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};


  app.get('/items', async (req, res) => {
    try {
      const items = await itemsCol.find().toArray();
      res.json(items);
    } catch (err) {
      console.error(err);
      res.status(500).send('Error fetching items');
    }
  });

  app.post('/auth/register', async (req, res) => {
    console.log("HI",req.body);
    const { email, password } = req.body;
    try {
      const existing = await usersCol.findOne({ email });
      if (existing) return res.status(400).json({ error: 'Email already in use' });

      const passwordHash = await bcrypt.hash(password, 12);
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const data = await usersCol.insertOne({
        email,
        passwordHash,
        isVerified: false,
        verificationToken,
        createdAt: new Date()
      });

      console.log("HI",data);

      const link = `${API_URL || `https://def5-2401-4900-1f26-309f-a100-ea63-53d-3d8.ngrok-free.app`}auth/verify/${verificationToken}`;
      console.log("HI1",link);
      const sendEmail = transporter.sendMail({
        to: email,
        subject: 'Please verify your account',
        html: `<p>Click <a href="${link}">here</a> to verify your email.</p>`
      });

      // Use Promise.race to timeout if sendMail takes too long
      const send = await Promise.race([
        sendEmail,
        new Promise((_, reject) => setTimeout(() => reject(new Error('Email timeout')), 8000))
      ]);

    if (send instanceof Error) {
      console.error(send);
      return res.status(500).json({ error: 'Email timeout' });
    }
      res.status(201).json({ message: 'User registered. Verification email sent.' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  app.get('/auth/verify/:token', async (req, res) => {
    try {
      console.log("in verify");
      const { token } = req.params;
      const user = await usersCol.findOne({ verificationToken: token });
      if (!user) return res.status(400).send('Invalid or expired token');

      await usersCol.updateOne(
        { verificationToken: token },
        { $set: { isVerified: true }, $unset: { verificationToken: '' } }
      );
      console.log("email verified")
      res.send('Email verified! You can now log in.');
    } catch (err) {
      console.error(err);
      res.status(500).send('Verification error');
    }
  });

  app.post('/auth/login', async (req, res) => {
    console.log("HI2",req.body);
    const { email, password } = req.body;
    console.log(email, password);
    try {
      const user = await usersCol.findOne({ email });
      if (!user) return res.status(400).json({ error: 'Invalid credentials' });
      if (!user.isVerified) return res.status(403).json({ error: 'Email not verified' });

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) return res.status(400).json({ error: 'Invalid credentials' });

      const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  app.post('/auth/resend-verification', async (req, res) => {
    const { email } = req.body;
    try {
      const user = await usersCol.findOne({ email });
      if (!user) return res.status(400).json({ error: 'Email not found' });
      if (user.isVerified) return res.status(400).json({ error: 'Email already verified' });
  
      const verificationToken = crypto.randomBytes(32).toString('hex');
      await usersCol.updateOne(
        { email },
        { $set: { verificationToken } }
      );
  
      const link = `${API_URL}/auth/verify/${verificationToken}`;
      await transporter.sendMail({
        to: email,
        subject: 'Please verify your account',
        html: `<p>Click <a href="${link}">here</a> to verify your email.</p>`
      });
  
      res.json({ message: 'Verification email sent again' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Resend verification failed' });
    }
  });
  

  app.post('/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
      const user = await usersCol.findOne({ email });
      if (!user) return res.status(400).json({ error: 'Email not found' });

      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = Date.now() + 1000 * 60 * 30; // 30 minutes

      await usersCol.updateOne({ email }, {
        $set: {
          resetToken,
          resetExpires
        }
      });

      const link = `${API_URL}/auth/reset-password/${resetToken}`;
      await transporter.sendMail({
        to: email,
        subject: 'Password Reset',
        html: `<p>Click <a href="${link}">here</a> to reset your password.</p>`
      });

      res.json({ message: 'Password reset email sent' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Reset request failed' });
    }
  });

  app.post('/auth/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
      const user = await usersCol.findOne({ resetToken: token, resetExpires: { $gt: Date.now() } });
      if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

      const passwordHash = await bcrypt.hash(password, 12);

      await usersCol.updateOne(
        { _id: user._id },
        {
          $set: { passwordHash },
          $unset: { resetToken: '', resetExpires: '' }
        }
      );

      res.json({ message: 'Password reset successful' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Reset failed' });
    }
  });

  app.post('/auth/google', async (req, res) => {
    const { idToken } = req.body;
    try {
      const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
      const payload = ticket.getPayload();

      let user = await usersCol.findOne({ googleId: payload.sub });
      if (!user) {
        const newUser = {
          email: payload.email,
          googleId: payload.sub,
          isVerified: true,
          createdAt: new Date()
        };
        const result = await usersCol.insertOne(newUser);
        user = { _id: result.insertedId, ...newUser };
      }

      const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token });
    } catch (err) {
      console.error(err);
      res.status(401).json({ error: 'Google authentication failed' });
    }
  });

  app.get('/protected', authenticate, async (req, res) => {
    res.json({ message: `Hello user ${req.userId}` });
  });


const messagesCol = db.collection('messages');
// Send a message
app.post('/chat/send', authenticate, async (req, res) => {
  const { receiverId, message } = req.body;
  console.log("chat", req.body);
  const senderId = req.userId; // get the sender's userId from the JWT

  try {
    const newMessage = {
      senderId,
      receiverId,
      message,
      timestamp: new Date(),
    };

    await messagesCol.insertOne(newMessage);
    res.status(200).json({ message: 'Message sent successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get messages between two users
app.get('/chat/:receiverId', authenticate, async (req, res) => {
  const receiverId = req.params.receiverId;
  const senderId = req.userId; // get the sender's userId from the JWT

  try {
    const messages = await messagesCol.find({
      $or: [
        { senderId, receiverId },
        { senderId: receiverId, receiverId: senderId },
      ],
    }).sort({ timestamp: 1 }).toArray(); // sort by timestamp in ascending order

    res.status(200).json({ messages });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});


app.get('/api/getReceiverId', authenticate, async (req, res) => {
  try {
    const userId = req.userId;  // Get userId from the JWT token
    let receiver = await usersCol.findOne({ _id: new ObjectId(userId) });  // Use new ObjectId()

    if (!receiver) {
      // If receiver doesn't exist, create a new one
      const newReceiverData = {
        _id: new ObjectId(userId),  // Use new ObjectId() here
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await usersCol.insertOne(newReceiverData);
      receiver = { _id: result.insertedId, ...newReceiverData };  // Add the new receiver data

      console.log(`Created new receiver with ID: ${receiver._id}`);
    }

    res.status(200).json({ receiverId: receiver._id });  // Return receiverId
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error fetching or creating receiver data' });
  }
});


// Get receiverName (using receiverId)
app.get('/api/getReceiverName/:receiverId', authenticate, async (req, res) => {
  try {
    const receiverId = req.params.receiverId;
    console.log('Received receiverId:', receiverId);

    const receiver = await usersCol.findOne({ _id: new ObjectId(receiverId) });

    if (receiver) {
      console.log('Receiver found:', receiver);
      
      // If name is missing, you could set a default value or return an appropriate error
      const receiverName = receiver.name || "test";
      
      res.status(200).json({ name: receiverName });
    } else {
      console.log('Receiver not found');
      res.status(404).json({ error: 'Receiver not found' });
    }
  } catch (err) {
    console.error('Error fetching receiver name:', err);
    res.status(500).json({ error: 'Error fetching receiver name' });
  }
});



  app.listen(PORT, () => {
    console.log(`Server running on ${API_URL || `http://localhost:${PORT}`}`);
  });
}

startServer().catch(err => {
  console.error(err);
  process.exit(1);
});
