const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Use the IPv4 address explicitly in the MongoDB URI
const mongoURI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/userdb';

// MongoDB connection using Mongoose
mongoose.connect(mongoURI);
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');

    // Start the server after connecting to MongoDB
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
});

// Create a user schema
const userSchema = new mongoose.Schema({
    username: String,
    email: {type: String, unique: true},
    password: String,
    phoneNumber: String 
});

const User = mongoose.model('User', userSchema);

// Create a MongoDB session store
const store = new MongoDBStore({
    uri: process.env.MONGODB_URI,
    collection: 'sessions'
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: store
}));

// Serve HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public','index.html'));
});

// Handle registration form submission
app.post('/register', async (req, res) => {
    try {
        const { username, email, phoneNumber, password } = req.body;

        // Check if the user already exists by username
        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Check if the user already exists by email
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ error: 'Email already in use' });
        }

        // Check if the user already exists by phone number
        const existingPhoneNumber = await User.findOne({ phoneNumber });
        if (existingPhoneNumber) {
            return res.status(400).json({ error: 'Phone number already in use' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({
            username,
            email,
            phoneNumber,
            password: hashedPassword
        });


        // Save the user to the database
        await newUser.save();
        res.send('Registration successful!');

    } catch (error) {
        console.error(error);
        res.status(500).send('Registration failed. Please try again.');
    }
})


// Route for user login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find the user by username
        const user = await User.findOne({ username });

        // Check if the user exists and the password is correct
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.user = user;
            res.send('Login successful!');
        } else {
            res.status(401).send('Invalid credentials');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Login failed. Please try again.');
    }
});

// Route for user logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
            res.status(500).send('Logout failed. Please try again.');
        } else {
            res.send('Logout successful!');
        }
    });
});

// Route to check if the user is logged in
app.get('/check-login', (req, res) => {
    if (req.session.user) {
        res.send(`Logged in as ${req.session.user.username}`);
    } else {
        res.send('Not logged in');
    }
});

// Middleware to handle errors
app.use((err, req, res, next) => {
    if (err instanceof mongoose.Error.ValidationError) {
        res.status(400).json({ error: err.message });
    } else {
        console.error(err);
        res.status(500).send('Something went wrong. Please try again later.');
    }
});