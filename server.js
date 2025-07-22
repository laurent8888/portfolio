const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const mysql = require('mysql2/promise');
const app = express();

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));

// Session setup
app.use(
    session({
        secret: 'my-secret',
        resave: false,
        saveUninitialized: true,
    })
);

// Database connection pool 
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'SQLconfigurator', // Replace with your MySQL password
    database: 'login_system',
});

// Routes
app.get('/', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.render('login', { error: 'Invalid username or password' });
        }

        const user = rows[0];

        // Validate password using bcrypt
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.render('login', { error: 'Invalid username or password' });
        }

        req.session.user = { id: user.id, username: user.username };
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Error during login:', error);
        res.render('login', { error: 'An error occurred, please try again.' });
    }
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.render('register', { error: 'Username and password are required.' });
    }

    try {
        // Check if the username already exists
        const [existingUser] = await db.query('SELECT * FROM users WHERE username = ?', [username]);

        if (existingUser.length > 0) {
            return res.render('register', { error: 'Username is already taken.' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save user to the database
        await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

        res.redirect('/login'); // Redirect to login page after successful registration
    } catch (err) {
        console.error('Error registering user:', err);
        res.render('register', { error: 'An error occurred while registering the user.' });
    }
});

app.get('/dashboard', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    res.render('dashboard', { user: req.session.user });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
