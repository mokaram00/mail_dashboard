import os
from mailcow import MailCow
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API configuration from environment variables
API_URL = os.getenv("MAILCOW_API_URL")
API_KEY = os.getenv("MAILCOW_API_KEY")

print(f"API URL: {API_URL}")
print(f"API Key: {API_KEY[:5]}...{API_KEY[-5:] if API_KEY else 'None'}")

# Create MailCow instance
try:
    mc = MailCow(url=API_URL, token=API_KEY, ssl_verify=False)
    print("MailCow instance created successfully")
    
    # Test getting mailboxes
    print("Getting mailboxes...")
    mailboxes = mc.mailbox.get()
    print(f"Found {len(mailboxes)} mailboxes")
    if mailboxes:
        print(f"First mailbox: {mailboxes[0]}")
    
    # Test getting domains
    print("Getting domains...")
    domains = mc.domain.get()
    print(f"Found {len(domains)} domains")
    if domains:
        print(f"First domain: {domains[0]}")
        
except Exception as e:
    print(f"Error: {e}")