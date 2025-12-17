const express = require('express');
const session = require('express-session');
const path = require('path');
const dotenv = require('dotenv');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const winston = require('winston');
const MailCowClient = require('ts-mailcow-api').default;

// Load environment variables
dotenv.config();

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'admin-server' },
  transports: [
    new winston.transports.File({ filename: path.join(__dirname, 'logs', 'error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(__dirname, 'logs', 'combined.log') })
  ]
});

// If we're not in production, also log to the console
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

const app = express();
const PORT = 5001;

// Database setup
const dbPath = path.join(__dirname, 'email_platforms.db');
const db = new sqlite3.Database(dbPath);

// Initialize database tables
function initDB() {
  logger.info('Initializing database tables');
  db.serialize(() => {
    // Create email_platforms table
    db.run(`CREATE TABLE IF NOT EXISTS email_platforms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      platform TEXT NOT NULL,
      notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) {
        logger.error('Error creating email_platforms table:', err);
      } else {
        logger.info('email_platforms table ready');
      }
    });
    
    // Create platforms table
    db.run(`CREATE TABLE IF NOT EXISTS platforms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      color TEXT DEFAULT '#4a90e2',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) {
        logger.error('Error creating platforms table:', err);
      } else {
        logger.info('platforms table ready');
      }
    });
    
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
      stmt.run(platform, (err) => {
        if (err) {
          logger.error('Error inserting platform:', { platform: platform, error: err });
        }
      });
    });
    stmt.finalize((err) => {
      if (err) {
        logger.error('Error finalizing statement:', err);
      } else {
        logger.info('Default platforms initialized');
      }
    });
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

// Initialize Mailcow client
const mailcowClient = new MailCowClient(MAILCOW_API_URL, MAILCOW_API_KEY);

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
  const isAuthenticated = username === ADMIN_USERNAME && password === ADMIN_PASSWORD;
  if (isAuthenticated) {
    logger.info('Admin authentication successful', { username });
  } else {
    logger.warn('Admin authentication failed', { username });
  }
  return isAuthenticated;
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

// Database functions
function addEmailPlatform(email, platform, notes = '', callback) {
  logger.info('Adding email platform mapping', { email, platform });
  db.run(
    'INSERT OR REPLACE INTO email_platforms (email, platform, notes, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
    [email, platform, notes],
    function(err) {
      if (err) {
        logger.error('Error adding email platform mapping', { email, platform, error: err });
      } else {
        logger.info('Email platform mapping added successfully', { email, platform, id: this.lastID });
      }
      callback(err, this.lastID);
    }
  );
}

function getEmailPlatform(email, callback) {
  logger.info('Getting email platform mapping', { email });
  db.get(
    'SELECT email, platform, notes, created_at, updated_at FROM email_platforms WHERE email = ?',
    [email],
    function(err, row) {
      if (err) {
        logger.error('Error getting email platform mapping', { email, error: err });
      } else if (row) {
        logger.info('Email platform mapping found', { email, platform: row.platform });
      } else {
        logger.info('Email platform mapping not found', { email });
      }
      callback(err, row);
    }
  );
}

function getAllEmailPlatforms(callback) {
  logger.info('Getting all email platform mappings');
  db.all(
    'SELECT email, platform, notes, created_at, updated_at FROM email_platforms ORDER BY platform, email',
    function(err, rows) {
      if (err) {
        logger.error('Error getting all email platform mappings', { error: err });
      } else {
        logger.info('All email platform mappings retrieved', { count: rows ? rows.length : 0 });
      }
      callback(err, rows);
    }
  );
}

function getPlatformStatistics(callback) {
  logger.info('Getting platform statistics');
  db.all(
    'SELECT platform, COUNT(*) as count FROM email_platforms GROUP BY platform ORDER BY count DESC',
    function(err, rows) {
      if (err) {
        logger.error('Error getting platform statistics', { error: err });
      } else {
        logger.info('Platform statistics retrieved', { count: rows ? rows.length : 0 });
      }
      callback(err, rows);
    }
  );
}

function getAllPlatforms(callback) {
  logger.info('Getting all platforms');
  db.all(
    'SELECT name, description, color FROM platforms ORDER BY name',
    function(err, rows) {
      if (err) {
        logger.error('Error getting all platforms', { error: err });
      } else {
        logger.info('All platforms retrieved', { count: rows ? rows.length : 0 });
      }
      callback(err, rows);
    }
  );
}

function deleteEmailPlatform(email, callback) {
  logger.info('Deleting email platform mapping', { email });
  db.run(
    'DELETE FROM email_platforms WHERE email = ?',
    [email],
    function(err) {
      if (err) {
        logger.error('Error deleting email platform mapping', { email, error: err });
      } else {
        logger.info('Email platform mapping deleted successfully', { email, changes: this.changes });
      }
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
  logger.info('Login attempt', { username });
  
  if (authenticateAdmin(username, password)) {
    req.session.admin_logged_in = true;
    req.session.admin_username = username;
    req.session.success = 'Successfully logged in!';
    logger.info('Successful login', { username });
    res.redirect('/');
  } else {
    req.session.error = 'Invalid credentials. Please try again.';
    logger.warn('Failed login attempt', { username });
    res.redirect('/login');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  const username = req.session.admin_username;
  req.session.destroy();
  req.session = null;
  logger.info('User logged out', { username });
  res.redirect('/login');
});

// Dashboard route (protected)
app.get('/', (req, res) => {
  if (!checkAdminAuth(req)) {
    req.session.warning = 'Please log in to access the dashboard.';
    logger.warn('Unauthorized access to dashboard');
    return res.redirect('/login');
  }
  
  logger.info('Dashboard accessed');
  
  // Fetch real data from Mailcow API
  Promise.all([
    mailcowClient.mailbox.get('all'),
    mailcowClient.domains.get('all')
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
    
    logger.info('Dashboard data fetched', { totalMailboxes, totalDomains });
    res.render('dashboard', { 
      stats: stats, 
      mailboxes: recentMailboxes,
      session: req.session
    });
  })
  .catch(error => {
    // Fallback to dummy data if API fails
    logger.error('Error fetching dashboard data from Mailcow API', { error: error.message });
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
    logger.warn('Unauthorized access to mailboxes');
    return res.redirect('/login');
  }
  
  logger.info('Mailboxes page accessed');
  
  mailcowClient.mailbox.get('all')
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
        logger.info('Mailboxes data processed', { count: processedMailboxes.length });
      } else if (mailboxesData && mailboxesData.error) {
        req.session.danger = `Error fetching mailboxes: ${mailboxesData.error}`;
        if (mailboxesData.details) {
          req.session.danger += ` Details: ${mailboxesData.details}`;
        }
        logger.error('Error fetching mailboxes', { error: mailboxesData.error });
        processedMailboxes = [];
      } else {
        req.session.warning = 'Unable to fetch mailboxes from Mailcow API.';
        logger.warn('Unable to fetch mailboxes from Mailcow API');
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
      logger.error('Error fetching mailboxes from Mailcow API', { error: error.message });
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
    logger.warn('Unauthorized access to create mailbox page');
    return res.redirect('/login');
  }
  
  logger.info('Create mailbox page accessed');
  
  mailcowClient.domains.get('all')
    .then(domainsData => {
      let availableDomains = ['bltnm.store']; // Fallback
      
      if (Array.isArray(domainsData)) {
        logger.debug('Raw domains data:', domainsData);
        // Handle different possible domain data structures
        availableDomains = domainsData
          .map(domainObj => {
            // Check various possible property names for domain
            if (typeof domainObj === 'string') {
              return domainObj;
            } else if (domainObj.domain) {
              return domainObj.domain;
            } else if (domainObj.name) {
              return domainObj.name;
            } else if (domainObj.hasOwnProperty('0')) {
              // If it's an array-like object with domain as first element
              return domainObj[0];
            }
            // Return undefined if we can't find the domain name
            return undefined;
          })
          .filter(domain => domain);
        logger.info('Domains fetched for create mailbox page', { count: availableDomains.length, rawCount: domainsData.length });
      } else if (domainsData && domainsData.error) {
        req.session.danger = `Error fetching domains: ${domainsData.error}`;
        if (domainsData.details) {
          req.session.danger += ` Details: ${domainsData.details}`;
        }
        logger.error('Error fetching domains for create mailbox page', { error: domainsData.error });
      } else {
        req.session.warning = 'Unable to fetch domains from Mailcow API. Using default domain.';
        logger.warn('Unable to fetch domains from Mailcow API. Using default domain.');
      }
      
      res.render('create_mail', { 
        categories: EMAIL_CATEGORIES, 
        domains: availableDomains,
        session: req.session
      });
    })
    .catch(error => {
      req.session.warning = 'Unable to fetch domains from Mailcow API. Using default domain.';
      logger.error('Error fetching domains from Mailcow API for create mailbox page', { error: error.message });
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
    logger.warn('Unauthorized access to create mailbox POST endpoint');
    return res.redirect('/login');
  }
  
  const { local_part, domain, password, name, category, quota, confirm_password } = req.body;
  logger.info('Create mailbox request received', { local_part, domain, name, category, quota });
  
  // Validate inputs
  if (!local_part || !domain || !password || !name) {
    req.session.danger = 'All fields are required.';
    logger.warn('Create mailbox failed: missing required fields');
    return res.redirect('/create');
  }
  
  // Validate password complexity
  const passwordValidation = validatePasswordComplexity(password);
  if (!passwordValidation.isValid) {
    req.session.danger = `Password complexity error: ${passwordValidation.message}`;
    logger.warn('Create mailbox failed: password complexity error', { message: passwordValidation.message });
    return res.redirect('/create');
  }
  
  // Confirm passwords match
  if (password !== confirm_password) {
    req.session.danger = 'Passwords do not match.';
    logger.warn('Create mailbox failed: passwords do not match');
    return res.redirect('/create');
  }
  
  // Call the Mailcow API to create mailbox
  mailcowClient.mailbox.create({
    local_part: local_part,
    domain: domain,
    password: password,
    password2: password,
    name: name,
    quota: parseInt(quota) || 1024,
    active: 1,
    force_pw_update: true,
    tls_enforce_in: true,
    tls_enforce_out: true
  })
    .then(result => {
      if (result && result.error) {
        req.session.danger = `Error creating mailbox: ${result.error}`;
        if (result.details) {
          req.session.danger += ` Details: ${JSON.stringify(result.details)}`;
        }
        logger.error('Error creating mailbox via Mailcow API', { local_part, domain, error: result.error });
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
        logger.error('Error creating mailbox via Mailcow API', { local_part, domain, error: errorMsg });
      } else {
        req.session.success = `Mailbox ${local_part}@${domain} created successfully!`;
        logger.info('Mailbox created successfully', { local_part, domain });
      }
      res.redirect('/create');
    })
    .catch(error => {
      req.session.danger = `Error creating mailbox: ${error.message}`;
      logger.error('Error creating mailbox', { local_part, domain, error: error.message });
      res.redirect('/create');
    });
});

// Delete mailbox route
app.post('/delete/:email', (req, res) => {
  if (!checkAdminAuth(req)) {
    req.session.warning = 'Please log in to access this page.';
    logger.warn('Unauthorized access to delete mailbox endpoint');
    return res.redirect('/login');
  }
  
  const email = req.params.email;
  logger.info('Delete mailbox request received', { email });
  
  // Parse email to get local_part and domain
  const emailParts = email.split('@');
  if (emailParts.length !== 2) {
    req.session.danger = 'Invalid email format.';
    logger.warn('Delete mailbox failed: invalid email format', { email });
    return res.redirect('/mailboxes');
  }
  
  const [local_part, domain] = emailParts;
  
  // Call the Mailcow API to delete mailbox
  mailcowClient.mailbox.delete({
    mailboxes: [`${local_part}@${domain}`]
  })
    .then(result => {
      if (result && result.error) {
        req.session.danger = `Error deleting mailbox: ${result.error}`;
        if (result.details) {
          req.session.danger += ` Details: ${JSON.stringify(result.details)}`;
        }
        logger.error('Error deleting mailbox via Mailcow API', { email, error: result.error });
      } else if (Array.isArray(result) && result.length > 0 && result[0].type === 'danger') {
        const errorMsg = result[0].msg || 'Unknown error';
        req.session.danger = `Error deleting mailbox: ${errorMsg}`;
        if (result[0].log) {
          req.session.danger += ` Technical details: ${result[0].log}`;
        }
        logger.error('Error deleting mailbox via Mailcow API', { email, error: errorMsg });
      } else {
        req.session.success = `Mailbox ${email} deleted successfully!`;
        logger.info('Mailbox deleted successfully', { email });
      }
      res.redirect('/mailboxes');
    })
    .catch(error => {
      req.session.danger = `Error deleting mailbox: ${error.message}`;
      logger.error('Error deleting mailbox', { email, error: error.message });
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
    logger.warn('Unauthorized access to email-platforms page');
    return res.redirect('/login');
  }
  
  logger.info('Email-platforms page accessed');
  
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
    logger.info('Email platform data fetched', { 
      emailPlatformsCount: emailPlatformsData ? emailPlatformsData.length : 0,
      platformStatsCount: platformStatsData ? platformStatsData.length : 0,
      platformsCount: platformsData ? platformsData.length : 0
    });
    res.render('email_platforms', {
      email_platforms: emailPlatformsData,
      platform_stats: platformStatsData,
      platforms: platformsData,
      session: req.session
    });
  })
  .catch(error => {
    req.session.danger = `Error fetching email platform data: ${error.message}`;
    logger.error('Error fetching email platform data', { error: error.message });
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
    logger.warn('Unauthorized access to email-platform API POST endpoint');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { email, platform, notes } = req.body;
  logger.info('Email-platform mapping request received', { email, platform });
  
  if (!email || !platform) {
    logger.warn('Email-platform mapping failed: missing email or platform');
    return res.status(400).json({ error: 'Email and platform are required' });
  }
  
  addEmailPlatform(email, platform, notes || '', (err, id) => {
    if (err) {
      logger.error('Failed to map email to platform', { email, platform, error: err });
      return res.status(500).json({ error: 'Failed to map email to platform' });
    }
    logger.info('Email mapped to platform successfully', { email, platform, id });
    res.json({ success: true, message: `Email ${email} mapped to platform ${platform}` });
  });
});

// API endpoint to get email-platform mapping
app.get('/api/email-platform/:email', (req, res) => {
  if (!checkAdminAuth(req)) {
    logger.warn('Unauthorized access to email-platform API GET endpoint');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const email = req.params.email;
  logger.info('Get email-platform mapping request received', { email });
  
  getEmailPlatform(email, (err, data) => {
    if (err) {
      logger.error('Database error while getting email-platform mapping', { email, error: err });
      return res.status(500).json({ error: 'Database error' });
    }
    if (data) {
      logger.info('Email-platform mapping found', { email, platform: data.platform });
      res.json(data);
    } else {
      logger.info('Email-platform mapping not found', { email });
      res.status(404).json({ error: 'Email not found' });
    }
  });
});

// API endpoint to update mailbox quota
app.put('/api/mailbox/quota', async (req, res) => {
  if (!checkAdminAuth(req)) {
    logger.warn('Unauthorized access to mailbox quota update endpoint');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { email, quota } = req.body;
  logger.info('Update mailbox quota request received', { email, quota });
  
  if (!email || quota === undefined) {
    logger.warn('Update mailbox quota failed: missing email or quota');
    return res.status(400).json({ error: 'Email and quota are required' });
  }
  
  try {
    const result = await mailcowClient.mailbox.edit({
      attr: { quota: parseInt(quota) },
      items: [email]
    });
    
    logger.info('Mailbox quota updated successfully', { email, quota });
    res.json({ success: true, message: `Quota for ${email} updated to ${quota} MB` });
  } catch (error) {
    logger.error('Error updating mailbox quota', { email, quota, error: error.message });
    res.status(500).json({ error: `Error updating mailbox quota: ${error.message}` });
  }
});

// API endpoint to delete email-platform mapping
app.delete('/api/email-platform/:email', (req, res) => {
  if (!checkAdminAuth(req)) {
    logger.warn('Unauthorized access to email-platform API DELETE endpoint');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const email = req.params.email;
  logger.info('Delete email-platform mapping request received', { email });
  
  deleteEmailPlatform(email, (err, changes) => {
    if (err) {
      logger.error('Failed to delete email mapping', { email, error: err });
      return res.status(500).json({ error: 'Failed to delete email mapping' });
    }
    if (changes > 0) {
      logger.info('Email mapping deleted successfully', { email, changes });
      res.json({ success: true, message: `Email ${email} mapping deleted` });
    } else {
      logger.info('Email mapping not found for deletion', { email });
      res.status(404).json({ error: 'Email not found' });
    }
  });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Admin server running on http://0.0.0.0:${PORT}`);
});