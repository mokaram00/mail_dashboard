const express = require('express');
const session = require('express-session');
const path = require('path');
const dotenv = require('dotenv');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

// Load environment variables
dotenv.config();

const app = express();
const PORT = 5001;

// Database setup
const dbPath = path.join(__dirname, 'email_platforms.db');
const db = new sqlite3.Database(dbPath);

// Initialize database tables
function initDB() {
  db.serialize(() => {
    // Create email_platforms table
    db.run(`CREATE TABLE IF NOT EXISTS email_platforms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      platform TEXT NOT NULL,
      notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Create platforms table
    db.run(`CREATE TABLE IF NOT EXISTS platforms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      color TEXT DEFAULT '#4a90e2',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Insert default platforms if they don't exist
    const defaultPlatforms = [
      ['Steam', 'Gaming platform for PC games', '#00adee'],
      ['Rockstar', 'Gaming platform for Rockstar games', '#fcaf17'],
      ['Epic Games', 'Gaming platform for Epic games', '#3a3a3a'],
      ['Ubisoft', 'Gaming platform for Ubisoft games', '#f5f5f5'],
      ['Microsoft', 'Microsoft services and accounts', '#00bcf2'],
      ['Google', 'Google services and accounts', '#4285f4'],
      ['Apple', 'Apple services and accounts', '#a2aaad'],
      ['Amazon', 'Amazon services and accounts', '#ff9900'],
      ['Netflix', 'Streaming service', '#e50914'],
      ['Spotify', 'Music streaming service', '#1db954'],
      ['Business', 'Business-related accounts', '#4a90e2'],
      ['Personal', 'Personal accounts', '#50c878'],
      ['Social Media', 'Social media accounts', '#8a3ab9'],
      ['Banking', 'Financial institutions', '#009900'],
      ['Other', 'Miscellaneous accounts', '#6c757d']
    ];
    
    const stmt = db.prepare('INSERT OR IGNORE INTO platforms (name, description, color) VALUES (?, ?, ?)');
    defaultPlatforms.forEach(platform => {
      stmt.run(platform);
    });
    stmt.finalize();
  });
}

// Initialize the database
initDB();

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'templates'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SECRET_KEY || 'fallback_secret_key_for_development',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Mailcow API configuration
const MAILCOW_API_URL = process.env.MAILCOW_API_URL;
const MAILCOW_API_KEY = process.env.MAILCOW_API_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Email categories
const EMAIL_CATEGORIES = [
  {id: 1, name: "Business", description: "Professional correspondence"},
  {id: 2, name: "Personal", description: "Personal emails"},
  {id: 3, name: "Marketing", description: "Promotional and marketing emails"},
  {id: 4, name: "Support", description: "Customer service and support emails"}
];

// Helper functions
function checkAdminAuth(req) {
  return req.session && req.session.admin_logged_in === true;
}

function authenticateAdmin(username, password) {
  return username === ADMIN_USERNAME && password === ADMIN_PASSWORD;
}

function generateStrongPassword(length = 16) {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
  let password = "";
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    password += charset[randomIndex];
  }
  return password;
}

function validatePasswordComplexity(password) {
  if (password.length < 8) {
    return { isValid: false, message: "Password must be at least 8 characters long" };
  }
  
  if (!/[A-Z]/.test(password)) {
    return { isValid: false, message: "Password must contain at least one uppercase letter" };
  }
  
  if (!/[a-z]/.test(password)) {
    return { isValid: false, message: "Password must contain at least one lowercase letter" };
  }
  
  if (!/[0-9]/.test(password)) {
    return { isValid: false, message: "Password must contain at least one number" };
  }
  
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return { isValid: false, message: "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)" };
  }
  
  return { isValid: true, message: "Password meets complexity requirements" };
}

// Mailcow API functions
async function createMailbox(local_part, domain, password, name, quota = 1024, active = true) {
  try {
    const url = `${MAILCOW_API_URL}/add/mailbox`;
    const data = {
      active: active ? "1" : "0",
      local_part: local_part,
      domain: domain,
      name: name,
      authsource: "mailcow",
      password: password,
      password2: password,
      quota: String(quota),
      force_pw_update: "1",
      tls_enforce_in: "1",
      tls_enforce_out: "1",
      tags: []
    };
    
    const response = await axios.post(url, data, {
      headers: {
        "X-API-Key": MAILCOW_API_KEY,
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "only.bltnm.store"
      },
      timeout: 30000,
    });
    
    return response.data;
  } catch (error) {
    console.error("Error creating mailbox:", error.response ? error.response.data : error.message);
    return { error: error.message, details: error.response ? error.response.data : null };
  }
}

async function deleteMailbox(local_part, domain) {
  try {
    const url = `${MAILCOW_API_URL}/delete/mailbox`;
    const data = [`${local_part}@${domain}`];
    
    const response = await axios.post(url, data, {
      headers: {
        "X-API-Key": MAILCOW_API_KEY,
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "only.bltnm.store"
      },
      timeout: 30000,
    });
    
    return response.data;
  } catch (error) {
    console.error("Error deleting mailbox:", error.response ? error.response.data : error.message);
    return { error: error.message, details: error.response ? error.response.data : null };
  }
}

async function getMailboxes() {
  try {
    const url = `${MAILCOW_API_URL}/get/mailbox/all`;
    
    const response = await axios.get(url, {
      headers: {
        "X-API-Key": MAILCOW_API_KEY,
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "only.bltnm.store"
      },
      timeout: 30000,
    });
    
    return response.data;
  } catch (error) {
    console.error("Error fetching mailboxes:", error.response ? error.response.data : error.message);
    return { error: error.message, details: error.response ? error.response.data : null };
  }
}

async function getDomains() {
  try {
    const url = `${MAILCOW_API_URL}/get/domain/all`;
    
    const response = await axios.get(url, {
      headers: {
        "X-API-Key": MAILCOW_API_KEY,
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "only.bltnm.store"
      },
      timeout: 30000,
    });
    
    return response.data;
  } catch (error) {
    console.error("Error fetching domains:", error.response ? error.response.data : error.message);
    return { error: error.message, details: error.response ? error.response.data : null };
  }
}

// Database functions
function addEmailPlatform(email, platform, notes = '', callback) {
  db.run(
    'INSERT OR REPLACE INTO email_platforms (email, platform, notes, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
    [email, platform, notes],
    function(err) {
      callback(err, this.lastID);
    }
  );
}

function getEmailPlatform(email, callback) {
  db.get(
    'SELECT email, platform, notes, created_at, updated_at FROM email_platforms WHERE email = ?',
    [email],
    callback
  );
}

function getAllEmailPlatforms(callback) {
  db.all(
    'SELECT email, platform, notes, created_at, updated_at FROM email_platforms ORDER BY platform, email',
    callback
  );
}

function getPlatformStatistics(callback) {
  db.all(
    'SELECT platform, COUNT(*) as count FROM email_platforms GROUP BY platform ORDER BY count DESC',
    callback
  );
}

function getAllPlatforms(callback) {
  db.all(
    'SELECT name, description, color FROM platforms ORDER BY name',
    callback
  );
}

function deleteEmailPlatform(email, callback) {
  db.run(
    'DELETE FROM email_platforms WHERE email = ?',
    [email],
    function(err) {
      callback(err, this.changes);
    }
  );
}

// Routes
// Login route
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (authenticateAdmin(username, password)) {
    req.session.admin_logged_in = true;
    req.session.admin_username = username;
    req.session.success = 'Successfully logged in!';
    res.redirect('/');
  } else {
    req.session.error = 'Invalid credentials. Please try again.';
    res.redirect('/login');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy();
  req.session = null;
  res.redirect('/login');
});

// Dashboard route (protected)
app.get('/', (req, res) => {
  if (!checkAdminAuth(req)) {
    req.session.warning = 'Please log in to access the dashboard.';
    return res.redirect('/login');
  }
  
  // Fetch real data from Mailcow API
  Promise.all([
    getMailboxes(),
    getDomains()
  ])
  .then(([mailboxesData, domainsData]) => {
    // Process data for dashboard stats
    let totalMailboxes = 0;
    let recentMailboxes = [];
    if (Array.isArray(mailboxesData)) {
      totalMailboxes = mailboxesData.length;
      recentMailboxes = mailboxesData.slice(0, 5); // First 5 mailboxes
    }
    
    let totalDomains = 0;
    if (Array.isArray(domainsData)) {
      totalDomains = domainsData.length;
    }
    
    const stats = {
      total_mailboxes: totalMailboxes,
      total_domains: totalDomains,
      categories: EMAIL_CATEGORIES.length,
      recent_activity: Math.min(totalMailboxes, 5)
    };
    
    res.render('dashboard', { 
      stats: stats, 
      mailboxes: recentMailboxes,
      session: req.session
    });
  })
  .catch(error => {
    // Fallback to dummy data if API fails
    const stats = {
      total_mailboxes: 0,
      total_domains: 0,
      categories: EMAIL_CATEGORIES.length,
      recent_activity: 0
    };
    
    req.session.warning = 'Unable to fetch data from Mailcow API. Showing demo data.';
    res.render('dashboard', { 
      stats: stats, 
      mailboxes: [],
      session: req.session
    });
  });
});

// Mailbox management routes
app.get('/mailboxes', (req, res) => {
  if (!checkAdminAuth(req)) {
    req.session.warning = 'Please log in to access this page.';
    return res.redirect('/login');
  }
  
  getMailboxes()
    .then(mailboxesData => {
      let processedMailboxes = [];
      
      if (Array.isArray(mailboxesData)) {
        processedMailboxes = mailboxesData.map((mailbox, i) => ({
          id: mailbox.id || i + 1,
          email: mailbox.username || 'unknown@example.com',
          name: mailbox.name || 'Unnamed User',
          category: 'General',
          created: mailbox.created || 'Unknown Date'
        }));
      } else if (mailboxesData && mailboxesData.error) {
        req.session.danger = `Error fetching mailboxes: ${mailboxesData.error}`;
        if (mailboxesData.details) {
          req.session.danger += ` Details: ${mailboxesData.details}`;
        }
        processedMailboxes = [];
      } else {
        req.session.warning = 'Unable to fetch mailboxes from Mailcow API.';
        processedMailboxes = [];
      }
      
      res.render('mailboxes', { 
        mailboxes: processedMailboxes, 
        categories: EMAIL_CATEGORIES,
        session: req.session
      });
    })
    .catch(error => {
      req.session.danger = `Error fetching mailboxes from Mailcow API: ${error.message}`;
      res.render('mailboxes', { 
        mailboxes: [], 
        categories: EMAIL_CATEGORIES,
        session: req.session
      });
    });
});

// Create mailbox route
app.get('/create', (req, res) => {
  if (!checkAdminAuth(req)) {
    req.session.warning = 'Please log in to access this page.';
    return res.redirect('/login');
  }
  
  getDomains()
    .then(domainsData => {
      let availableDomains = ['bltnm.store']; // Fallback
      
      if (Array.isArray(domainsData)) {
        availableDomains = domainsData
          .map(domain => domain.domain)
          .filter(domain => domain);
      } else if (domainsData && domainsData.error) {
        req.session.danger = `Error fetching domains: ${domainsData.error}`;
        if (domainsData.details) {
          req.session.danger += ` Details: ${domainsData.details}`;
        }
      } else {
        req.session.warning = 'Unable to fetch domains from Mailcow API. Using default domain.';
      }
      
      res.render('create_mail', { 
        categories: EMAIL_CATEGORIES, 
        domains: availableDomains,
        session: req.session
      });
    })
    .catch(error => {
      req.session.warning = 'Unable to fetch domains from Mailcow API. Using default domain.';
      res.render('create_mail', { 
        categories: EMAIL_CATEGORIES, 
        domains: ['bltnm.store'], // Fallback
        session: req.session
      });
    });
});

app.post('/create', (req, res) => {
  if (!checkAdminAuth(req)) {
    req.session.warning = 'Please log in to access this page.';
    return res.redirect('/login');
  }
  
  const { local_part, domain, password, name, category, quota, confirm_password } = req.body;
  
  // Validate inputs
  if (!local_part || !domain || !password || !name) {
    req.session.danger = 'All fields are required.';
    return res.redirect('/create');
  }
  
  // Validate password complexity
  const passwordValidation = validatePasswordComplexity(password);
  if (!passwordValidation.isValid) {
    req.session.danger = `Password complexity error: ${passwordValidation.message}`;
    return res.redirect('/create');
  }
  
  // Confirm passwords match
  if (password !== confirm_password) {
    req.session.danger = 'Passwords do not match.';
    return res.redirect('/create');
  }
  
  // Call the Mailcow API to create mailbox
  createMailbox(local_part, domain, password, name, parseInt(quota) || 1024)
    .then(result => {
      if (result && result.error) {
        req.session.danger = `Error creating mailbox: ${result.error}`;
        if (result.details) {
          req.session.danger += ` Details: ${JSON.stringify(result.details)}`;
        }
      } else if (Array.isArray(result) && result.length > 0 && result[0].type === 'danger') {
        const errorMsg = result[0].msg || 'Unknown error';
        req.session.danger = `Error creating mailbox: ${errorMsg}`;
        // Special handling for password complexity errors
        if (errorMsg === 'password_complexity') {
          req.session.info = 'Try a more complex password with uppercase, lowercase, numbers, and special characters.';
        }
        if (result[0].log) {
          req.session.danger += ` Technical details: ${result[0].log}`;
        }
      } else {
        req.session.success = `Mailbox ${local_part}@${domain} created successfully!`;
      }
      res.redirect('/create');
    })
    .catch(error => {
      req.session.danger = `Error creating mailbox: ${error.message}`;
      res.redirect('/create');
    });
});

// Delete mailbox route
app.post('/delete/:email', (req, res) => {
  if (!checkAdminAuth(req)) {
    req.session.warning = 'Please log in to access this page.';
    return res.redirect('/login');
  }
  
  const email = req.params.email;
  
  // Parse email to get local_part and domain
  const emailParts = email.split('@');
  if (emailParts.length !== 2) {
    req.session.danger = 'Invalid email format.';
    return res.redirect('/mailboxes');
  }
  
  const [local_part, domain] = emailParts;
  
  // Call the Mailcow API to delete mailbox
  deleteMailbox(local_part, domain)
    .then(result => {
      if (result && result.error) {
        req.session.danger = `Error deleting mailbox: ${result.error}`;
        if (result.details) {
          req.session.danger += ` Details: ${JSON.stringify(result.details)}`;
        }
      } else if (Array.isArray(result) && result.length > 0 && result[0].type === 'danger') {
        const errorMsg = result[0].msg || 'Unknown error';
        req.session.danger = `Error deleting mailbox: ${errorMsg}`;
        if (result[0].log) {
          req.session.danger += ` Technical details: ${result[0].log}`;
        }
      } else {
        req.session.success = `Mailbox ${email} deleted successfully!`;
      }
      res.redirect('/mailboxes');
    })
    .catch(error => {
      req.session.danger = `Error deleting mailbox: ${error.message}`;
      res.redirect('/mailboxes');
    });
});

// API endpoint to generate passwords
app.get('/api/generate-password', (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const password = generateStrongPassword();
  res.json({ password: password });
});

// Categories management
app.get('/categories', (req, res) => {
  if (!checkAdminAuth(req)) {
    req.session.warning = 'Please log in to access this page.';
    return res.redirect('/login');
  }
  
  res.render('categories', { 
    categories: EMAIL_CATEGORIES,
    session: req.session
  });
});

// Email-platform management routes
app.get('/email-platforms', (req, res) => {
  if (!checkAdminAuth(req)) {
    req.session.warning = 'Please log in to access this page.';
    return res.redirect('/login');
  }
  
  Promise.all([
    new Promise((resolve, reject) => {
      getAllEmailPlatforms((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    }),
    new Promise((resolve, reject) => {
      getPlatformStatistics((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    }),
    new Promise((resolve, reject) => {
      getAllPlatforms((err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    })
  ])
  .then(([emailPlatformsData, platformStatsData, platformsData]) => {
    res.render('email_platforms', {
      email_platforms: emailPlatformsData,
      platform_stats: platformStatsData,
      platforms: platformsData,
      session: req.session
    });
  })
  .catch(error => {
    req.session.danger = `Error fetching email platform data: ${error.message}`;
    res.render('email_platforms', {
      email_platforms: [],
      platform_stats: [],
      platforms: [],
      session: req.session
    });
  });
});

// API endpoint to add/update email-platform mapping
app.post('/api/email-platform', (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { email, platform, notes } = req.body;
  
  if (!email || !platform) {
    return res.status(400).json({ error: 'Email and platform are required' });
  }
  
  addEmailPlatform(email, platform, notes || '', (err, id) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to map email to platform' });
    }
    res.json({ success: true, message: `Email ${email} mapped to platform ${platform}` });
  });
});

// API endpoint to get email-platform mapping
app.get('/api/email-platform/:email', (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const email = req.params.email;
  
  getEmailPlatform(email, (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (data) {
      res.json(data);
    } else {
      res.status(404).json({ error: 'Email not found' });
    }
  });
});

// API endpoint to delete email-platform mapping
app.delete('/api/email-platform/:email', (req, res) => {
  if (!checkAdminAuth(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const email = req.params.email;
  
  deleteEmailPlatform(email, (err, changes) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete email mapping' });
    }
    if (changes > 0) {
      res.json({ success: true, message: `Email ${email} mapping deleted` });
    } else {
      res.status(404).json({ error: 'Email not found' });
    }
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Admin server running on http://0.0.0.0:${PORT}`);
});