const { createMailbox, deleteMailbox, getMailboxes, getDomains, updateMailboxQuota } = require('./mailcow');

console.log('Mailcow module loaded successfully!');
console.log('Available functions:');
console.log('- createMailbox');
console.log('- deleteMailbox');
console.log('- getMailboxes');
console.log('- getDomains');
console.log('- updateMailboxQuota');