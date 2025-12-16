const express = require('express');
const session = require('express-session');
const path = require('path');
const imap = require('imap');
const { simpleParser } = require('mailparser');
const { promisify } = require('util');

const app = express();
const PORT = 5000;

// Middleware
// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'templates'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'supersecretkey',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));

const IMAP_SERVER = 'mail.bltnm.store';
const IMAP_PORT = 993;

// Routes
app.get('/', (req, res) => {
  res.render('login');
});

app.post('/', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // Test IMAP connection
    const client = new imap({
      user: email,
      password: password,
      host: IMAP_SERVER,
      port: IMAP_PORT,
      tls: true,
      tlsOptions: { rejectUnauthorized: false }
    });
    
    const connectAsync = promisify(client.connect).bind(client);
    await connectAsync();
    
    req.session.email_user = email;
    req.session.password = password;
    
    client.end();
    res.redirect('/inbox');
  } catch (error) {
    console.error('Authentication failed:', error);
    res.render('login', { error: 'Authentication failed! Check your email or password.' });
  }
});

app.get('/inbox', async (req, res) => {
  if (!req.session.email_user) {
    return res.redirect('/');
  }
  
  const email_user = req.session.email_user;
  const password = req.session.password;
  
  let messages_list = [];
  
  try {
    const client = new imap({
      user: email_user,
      password: password,
      host: IMAP_SERVER,
      port: IMAP_PORT,
      tls: true,
      tlsOptions: { rejectUnauthorized: false }
    });
    
    const connectAsync = promisify(client.connect).bind(client);
    const openBoxAsync = promisify(client.openBox).bind(client);
    const searchAsync = promisify(client.search).bind(client);
    const fetchAsync = promisify(client.fetch).bind(client);
    
    await connectAsync();
    await openBoxAsync('INBOX');
    
    const results = await searchAsync(['ALL']);
    const fetch = client.fetch(results, { bodies: '' });
    
    const messages = await new Promise((resolve, reject) => {
      const messages = [];
      
      fetch.on('message', (msg, seqno) => {
        msg.on('body', (stream, info) => {
          simpleParser(stream, (err, parsed) => {
            if (err) return;
            messages.push({
              from: parsed.from ? parsed.from.text : 'Unknown',
              subject: parsed.subject || '(No Subject)'
            });
          });
        });
      });
      
      fetch.once('error', reject);
      fetch.once('end', () => resolve(messages));
    });
    
    messages_list = messages;
    client.end();
  } catch (error) {
    console.error('Failed to fetch emails:', error);
    messages_list = [];
  }
  
  res.render('inbox', { messages: messages_list, email: email_user });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});