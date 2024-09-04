import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

dotenv.config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'adminpassword123';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://investapi:investapi@investapi.j5fxg.mongodb.net/investapi';


mongoose.connect(MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));


// Schemas

const messageSchema = new mongoose.Schema({
    from: { type: String, enum: ['admin', 'user'], required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    amount: { type: Number, default: 0 },
    profitBalance: { type: Number, default: 0 },
    referralCode: { type: String, unique: true },
    referralLink: { type: String, unique: true },
    referrals: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    points: { type: Number, default: 0 },
    lastDeposit: { type: Date },
    isBlocked: { type: Boolean, default: false },
    messages: [messageSchema]
});

const depositSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: Number,
    profitBalance: { type: Number, default: 0 },
    lastProfitUpdate: { type: Date, default: Date.now },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }
});

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: { type: Number, required: true },
    paymentMethod: { type: String, required: true },
    cryptoWalletType: { type: String },
    cryptoWalletAddress: { type: String },
    accountName: { type: String },
    accountNumber: { type: String },
    bankName: { type: String },
    bankBranch: { type: String },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }
});

// Models
const User = mongoose.model('User', userSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Middleware
app.use(express.json());

app.use(cors({
    origin: [
        process.env.CLIENT_ORIGIN || 'https://jpmorganfx.vercel.app',
        'https://jpmorganfx.vercel.app/register',
        'https://jpmorganfx.vercel.app/login'
    ],
    credentials: true
}));



const generateReferralCode = () => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from({ length: 8 }, () => characters.charAt(Math.floor(Math.random() * characters.length))).join('');
};

const requireAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        req.userId = decoded.userId;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        next();
    });
};

// Default route to handle GET requests to the root URL
app.get('/', (req, res) => {
    res.send('Welcome to the API service!');
});

// Endpoint to get deposit and profit messages for a user
app.get('/api/user/messages', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Assuming deposit and profit messages are stored in user.messages
        const messages = user.messages.filter(msg => msg.content.includes('deposit') || msg.content.includes('profit'));

        res.status(200).json({ messages });
    } catch (error) {
        console.error('Error retrieving deposit/profit messages:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Endpoint to post a message from the user
app.post('/api/user/message', requireAuth, async (req, res) => {
    const { content } = req.body;
    console.log('Received message content:', content);  // Log received message content
    try {
      const user = await User.findById(req.userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      user.messages.push({ from: 'user', content });
      await user.save();
      res.status(201).json({ message: 'Message posted successfully' });
    } catch (error) {
      console.error('Error posting message:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  


const updateProfitBalance = async (userId) => {
    const deposits = await Deposit.find({ userId, status: 'approved' });
    if (deposits.length === 0) return;

    const now = new Date();
    let totalProfitToAdd = 0;

    for (const deposit of deposits) {
        const elapsedTime = now.getTime() - deposit.lastProfitUpdate.getTime();
        const daysElapsed = Math.floor(elapsedTime / (1000 * 60 * 60 * 24));

        if (daysElapsed > 0) {
            const dailyProfit = (deposit.amount * 0.2) / 7;
            const profitToAdd = dailyProfit * daysElapsed;

            totalProfitToAdd += profitToAdd;
            deposit.profitBalance += profitToAdd;
            deposit.lastProfitUpdate = now;
            await deposit.save();
        }
    }

    const user = await User.findById(userId);
    if (user) {
        user.profitBalance += totalProfitToAdd;
        await user.save();
    }
};

const calculateReferralBonus = async (userId) => {
    const user = await User.findById(userId).populate('referrals');
    if (!user) return;

    let totalBonus = 0;
    user.referrals.forEach(referral => {
        if (referral.referrals.length >= 5) {
            totalBonus += 100;
        }
    });

    if (totalBonus > 0) {
        user.amount += totalBonus;
        await user.save();
    }
};

// User Routes
app.post('/api/register', async (req, res) => {
    const { username, email, password, referral } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            username,
            email,
            password: hashedPassword,
            referralCode: generateReferralCode(),
            referralLink: `https://your-domain.com/register?referral=${generateReferralCode()}`
        });

        if (referral) {
            const referrer = await User.findOne({ referralCode: referral });
            if (referrer) {
                referrer.referrals.push(user._id);
                referrer.points += 1;

                // Calculate bonus for the referrer
                if (referrer.points >= 5) {
                    referrer.amount += 100;
                    referrer.points = 0;
                }

                await referrer.save();
            }
        }

        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        if (error.code === 11000) {
            res.status(400).json({ error: 'Email or referral code already exists' });
        } else {
            res.status(500).json({ error: 'Internal server error' });
        }
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email }).select('+password');
        if (user && !user.isBlocked && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });
            res.status(200).json({ token });
        } else {
            res.status(401).json({ error: 'Invalid credentials or account is blocked' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Deposit Route
app.post('/api/deposit', requireAuth, async (req, res) => {
    const { amount } = req.body;
    try {
      const user = await User.findById(req.userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      const now = new Date();
      const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  
      // Check if a deposit was made in the last 7 days
      if (user.lastDeposit && user.lastDeposit > sevenDaysAgo) {
        return res.status(400).json({ error: 'Deposit already made within the last 7 days' });
      }
  
      user.lastDeposit = now;
      user.amount += amount; // Update user balance
      await user.save();
  
      const deposit = new Deposit({
        userId: req.userId,
        amount,
      });
  
      await deposit.save();
      res.status(201).json({ message: 'Deposit successful' });
    } catch (error) {
      console.error('Error during deposit:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  

app.post('/api/withdraw', requireAuth, async (req, res) => {
    const { amount, paymentMethod, cryptoWalletType, cryptoWalletAddress, accountName, accountNumber, bankName, bankBranch } = req.body;
    try {
        const user = await User.findById(req.userId);
        if (!user || user.amount < amount) {
            return res.status(400).json({ error: 'Insufficient funds or invalid user' });
        }

        user.amount -= amount;
        await user.save();

        const withdrawal = new Withdrawal({
            userId: req.userId,
            amount,
            paymentMethod,
            cryptoWalletType,
            cryptoWalletAddress,
            accountName,
            accountNumber,
            bankName,
            bankBranch
        });

        await withdrawal.save();
        res.status(201).json({ message: 'Withdrawal request submitted' });
    } catch (error) {
        console.error('Error during withdrawal:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Password reset routes
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'No user found with this email.' });
        }

        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        const mailOptions = {
            to: user.email,
            from: 'passwordreset@yourdomain.com',
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested to reset your password.\n\n
            Please click on the following link, or paste it into your browser, to complete the process:\n\n
            http://${req.headers.host}/reset/${token}\n\n
            If you did not request this, please ignore this email and your password will remain unchanged.\n`,
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Password reset link sent to your email address.' });

    } catch (error) {
        res.status(500).json({ message: 'Error sending reset link. Please try again.' });
    }
});


app.get('/api/user/dashboard', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        await updateProfitBalance(user._id);
        await calculateReferralBonus(user._id);

        res.status(200).json({
            username: user.username,
            email: user.email,
            amount: user.amount,
            profitBalance: user.profitBalance,
            referralCode: user.referralCode,
            referralLink: user.referralLink,
            referrals: user.referrals.length,
            messages: user.messages
        });
    } catch (error) {
        console.error('Error retrieving user dashboard:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        res.status(200).json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/admin/message', requireAdmin, async (req, res) => {
    const { userId, content } = req.body;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.messages.push({ from: 'admin', content });
        await user.save();
        res.status(200).json({ message: 'Message sent to user' });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/admin/block-user/:userId', requireAdmin, async (req, res) => {
    const { userId } = req.params;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.isBlocked = true;
        await user.save();
        res.status(200).json({ message: 'User blocked successfully' });
    } catch (error) {
        console.error('Error blocking user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/admin/unblock-user/:userId', requireAdmin, async (req, res) => {
    const { userId } = req.params;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.isBlocked = false;
        await user.save();
        res.status(200).json({ message: 'User unblocked successfully' });
    } catch (error) {
        console.error('Error unblocking user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
    try {
        const users = await User.find({});
        const deposits = await Deposit.find({});
        const withdrawals = await Withdrawal.find({});
        res.status(200).json({ users, deposits, withdrawals });
    } catch (error) {
        console.error('Error retrieving admin dashboard:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// In your Express app
app.post('/api/messages', async (req, res) => {
    const { userId, content } = req.body;
    try {
      const newMessage = new Message({ userId, content });
      await newMessage.save();
      res.status(200).json(newMessage);
    } catch (error) {
      res.status(500).json({ error: 'Error sending message' });
    }
  });
  
  app.get('/api/messages/:userId', async (req, res) => {
    const { userId } = req.params;
    try {
      const messages = await Message.find({ userId });
      res.status(200).json(messages);
    } catch (error) {
      res.status(500).json({ error: 'Error retrieving messages' });
    }
  });
  

app.listen(5000, () => {
    console.log('Server is running on port 5000');
});
