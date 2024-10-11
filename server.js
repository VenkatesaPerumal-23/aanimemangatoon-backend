const express = require('express');
const mongoose = require('mongoose');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const JWT_SECRET = 'my-secret-key';

// In-memory array to simulate user storage
const users = [];

// Rate limiting to avoid API abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
});
app.use(limiter);

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/webtoonDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

// Webtoon schema
const webtoonSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  characters: String,
}, { collection: 'webtoons' });

const Webtoon = mongoose.model('Webtoon', webtoonSchema);

// Middleware for checking JWT token
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization');

  try {
    // Extract the token after "Bearer"
    const extractedToken = token.split(' ')[1];

    // Verify the token
    const verified = jwt.verify(extractedToken, JWT_SECRET);
    req.user = verified; // Attach verified user to the request
    next(); // Proceed to the next middleware or route handler
  } catch (err) {
    res.status(400).json({ error: 'Invalid token provided' });
  }
};

// Input validation middleware for webtoon
const validateWebtoon = [
  body('title').isString().withMessage('Title must be a string'),
  body('description').isString().withMessage('Description must be a string'),
  body('characters').optional().isString().withMessage('Characters must be a string if provided'),
];


// JWT Authentication Routes

// Register user and generate JWT token
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if the user already exists
  const existingUser = users.find(user => user.username === username);
  if (existingUser) {
    return res.status(400).json({ error: 'User already exists' });
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Add user to in-memory "users" array 
  const newUser = { username, password: hashedPassword };
  users.push(newUser);

  // Generate JWT token for the new user
  const token = jwt.sign({ username: newUser.username }, JWT_SECRET, { expiresIn: '1h' });

  res.json({ message: 'User registered successfully', token });
});

// Login user and verify JWT token if provided
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find the user in the in-memory store
  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  // Check if the password matches
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  // Generate JWT token
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });

  res.json({ message: 'Logged in successfully', token });
});


// Routes

// GET /webtoons: Fetch all webtoons
app.get('/webtoons', async (req, res) => {
  try {
    const webtoons = await Webtoon.find();
    res.json(webtoons);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /webtoons/:id Fetch a specific webtoon by its ID
app.get('/webtoons/:id', async (req, res) => {
  try {
    const webtoon = await Webtoon.findById(req.params.id);
    if (!webtoon) return res.status(404).json({ error: 'Webtoon not found' });
    res.json(webtoon);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /webtoons: Add a new webtoon (protected route)
app.post('/webtoons', authenticateJWT, validateWebtoon, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { title, description, characters } = req.body;
    const newWebtoon = new Webtoon({ title, description, characters });
    await newWebtoon.save();
    res.status(201).json(newWebtoon);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /webtoons/:id Delete a specific webtoon by its ID (protected route)
app.delete('/webtoons/:id', authenticateJWT, async (req, res) => {
  try {
    const webtoon = await Webtoon.findByIdAndDelete(req.params.id);
    if (!webtoon) return res.status(404).json({ error: 'Webtoon not found' });
    res.json({ message: 'Webtoon deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
