from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from mailcow_api import create_mailbox, delete_mailbox, get_mailboxes, get_domains
import os
from dotenv import load_dotenv
import re
import secrets
import string
from database import init_db, add_email_platform, get_email_platform, get_all_email_platforms, get_platform_statistics, get_all_platforms, delete_email_platform

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback_secret_key_for_development")

# Admin credentials (in production, store securely in environment variables or database)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Email categories
EMAIL_CATEGORIES = [
    {"id": 1, "name": "Business", "description": "Professional correspondence"},
    {"id": 2, "name": "Personal", "description": "Personal emails"},
    {"id": 3, "name": "Marketing", "description": "Promotional and marketing emails"},
    {"id": 4, "name": "Support", "description": "Customer service and support emails"}
]

def check_admin_auth():
    """Check if user is authenticated as admin"""
    return session.get('admin_logged_in') is True

def authenticate_admin(username, password):
    """Authenticate admin credentials"""
    # In production, use proper password hashing
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def generate_strong_password(length=16):
    """
    Generate a strong password that meets Mailcow requirements
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Check if password meets requirements
        if (any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
            and len(password) >= 8):
            return password

def validate_password_complexity(password):
    """
    Validate password complexity according to Mailcow requirements
    Minimum 8 characters with at least:
    - 1 uppercase letter
    - 1 lowercase letter
    - 1 number
    - 1 special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)"
    
    return True, "Password meets complexity requirements"

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if authenticate_admin(username, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash("Successfully logged in!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials. Please try again.", "danger")
    
    return render_template("login.html")

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# Dashboard route (protected)
@app.route("/")
def dashboard():
    if not check_admin_auth():
        flash("Please log in to access the dashboard.", "warning")
        return redirect(url_for("login"))
    
    # Fetch real data from Mailcow API
    try:
        mailboxes_data = get_mailboxes()
        domains_data = get_domains()
        
        # Process data for dashboard stats
        if isinstance(mailboxes_data, list):
            total_mailboxes = len(mailboxes_data)
            recent_mailboxes = mailboxes_data[:5]  # First 5 mailboxes
        else:
            total_mailboxes = 0
            recent_mailboxes = []
            
        if isinstance(domains_data, list):
            total_domains = len(domains_data)
        else:
            total_domains = 0
            
        stats = {
            "total_mailboxes": total_mailboxes,
            "total_domains": total_domains,
            "categories": len(EMAIL_CATEGORIES),
            "recent_activity": min(total_mailboxes, 5)
        }
    except Exception as e:
        # Fallback to dummy data if API fails
        stats = {
            "total_mailboxes": 0,
            "total_domains": 0,
            "categories": len(EMAIL_CATEGORIES),
            "recent_activity": 0
        }
        recent_mailboxes = []
        flash("Unable to fetch data from Mailcow API. Showing demo data.", "warning")
    
    return render_template("dashboard.html", stats=stats, mailboxes=recent_mailboxes)

# Mailbox management routes
@app.route("/mailboxes")
def list_mailboxes():
    if not check_admin_auth():
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login"))
    
    try:
        mailboxes_data = get_mailboxes()
        if not isinstance(mailboxes_data, list):
            # Handle error case
            if isinstance(mailboxes_data, dict) and "error" in mailboxes_data:
                flash(f"Error fetching mailboxes: {mailboxes_data['error']}", "danger")
                if "details" in mailboxes_data:
                    flash(f"Details: {mailboxes_data['details']}", "danger")
            else:
                flash("Unable to fetch mailboxes from Mailcow API.", "warning")
            mailboxes_data = []
    except Exception as e:
        mailboxes_data = []
        flash(f"Error fetching mailboxes from Mailcow API: {str(e)}", "danger")
    
    # Process mailboxes data to match our template expectations
    processed_mailboxes = []
    for i, mailbox in enumerate(mailboxes_data):
        processed_mailboxes.append({
            "id": mailbox.get("id", i+1),
            "email": mailbox.get("username", "unknown@example.com"),
            "name": mailbox.get("name", "Unnamed User"),
            "category": "General",  # In a real implementation, this would come from our database
            "created": mailbox.get("created", "Unknown Date")
        })
    
    return render_template("mailboxes.html", mailboxes=processed_mailboxes, categories=EMAIL_CATEGORIES)

# Create mailbox route
@app.route("/create", methods=["GET", "POST"])
def create():
    if not check_admin_auth():
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login"))
    
    # Get available domains for the dropdown
    try:
        domains_data = get_domains()
        if isinstance(domains_data, list):
            available_domains = [domain.get("domain") for domain in domains_data if domain.get("domain")]
        else:
            # Handle error case
            if isinstance(domains_data, dict) and "error" in domains_data:
                flash(f"Error fetching domains: {domains_data['error']}", "danger")
                if "details" in domains_data:
                    flash(f"Details: {domains_data['details']}", "danger")
            available_domains = ["bltnm.store"]  # Fallback
    except Exception as e:
        available_domains = ["bltnm.store"]  # Fallback
        flash("Unable to fetch domains from Mailcow API. Using default domain.", "warning")
    
    if request.method == "POST":
        local_part = request.form["local_part"]
        domain = request.form["domain"]
        password = request.form["password"]
        name = request.form["name"]
        category = request.form.get("category", "General")
        quota = int(request.form.get("quota", 1024))

        # Validate inputs
        if not all([local_part, domain, password, name]):
            flash("All fields are required.", "danger")
            return render_template("create_mail.html", categories=EMAIL_CATEGORIES, domains=available_domains)
        
        # Validate password complexity
        is_valid, message = validate_password_complexity(password)
        if not is_valid:
            flash(f"Password complexity error: {message}", "danger")
            return render_template("create_mail.html", categories=EMAIL_CATEGORIES, domains=available_domains)
        
        # Confirm passwords match
        confirm_password = request.form["confirm_password"]
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("create_mail.html", categories=EMAIL_CATEGORIES, domains=available_domains)
        
        # Call the Mailcow API to create mailbox
        try:
            result = create_mailbox(local_part, domain, password, name, quota)
            
            if isinstance(result, dict):
                if "error" in result:
                    flash(f"Error creating mailbox: {result['error']}", "danger")
                    if "details" in result:
                        flash(f"Details: {result['details']}", "danger")
                elif isinstance(result, list) and len(result) > 0 and result[0].get("type") == "danger":
                    error_msg = result[0].get("msg", "Unknown error")
                    flash(f"Error creating mailbox: {error_msg}", "danger")
                    # Special handling for password complexity errors
                    if error_msg == "password_complexity":
                        flash("Try a more complex password with uppercase, lowercase, numbers, and special characters.", "info")
                    if "log" in result[0]:
                        flash(f"Technical details: {result[0]['log']}", "danger")
                else:
                    flash(f"Mailbox {local_part}@{domain} created successfully!", "success")
            else:
                flash(f"Mailbox {local_part}@{domain} created successfully!", "success")
        except Exception as e:
            flash(f"Error creating mailbox: {str(e)}", "danger")
        
        return redirect(url_for("create"))

    return render_template("create_mail.html", categories=EMAIL_CATEGORIES, domains=available_domains)

# Delete mailbox route
@app.route("/delete/<email>", methods=["POST"])
def delete(email):
    if not check_admin_auth():
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login"))
    
    # Parse email to get local_part and domain
    try:
        local_part, domain = email.split("@")
    except ValueError:
        flash("Invalid email format.", "danger")
        return redirect(url_for("list_mailboxes"))
    
    # Call the Mailcow API to delete mailbox
    try:
        result = delete_mailbox(local_part, domain)
        
        if isinstance(result, dict):
            if "error" in result:
                flash(f"Error deleting mailbox: {result['error']}", "danger")
                if "details" in result:
                    flash(f"Details: {result['details']}", "danger")
            elif isinstance(result, list) and len(result) > 0 and result[0].get("type") == "danger":
                error_msg = result[0].get("msg", "Unknown error")
                flash(f"Error deleting mailbox: {error_msg}", "danger")
            else:
                flash(f"Mailbox {email} deleted successfully!", "success")
        else:
            flash(f"Mailbox {email} deleted successfully!", "success")
    except Exception as e:
        flash(f"Error deleting mailbox: {str(e)}", "danger")
    
    return redirect(url_for("list_mailboxes"))

# API endpoint to generate passwords
@app.route("/api/generate-password")
def api_generate_password():
    if not check_admin_auth():
        return {"error": "Unauthorized"}, 401
    
    password = generate_strong_password()
    return {"password": password}

# Categories management
@app.route("/categories")
def categories():
    if not check_admin_auth():
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login"))
    
    return render_template("categories.html", categories=EMAIL_CATEGORIES)

# Email-platform management routes
@app.route("/email-platforms")
def email_platforms():
    if not check_admin_auth():
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login"))
    
    # Get all email-platform mappings
    email_platforms_data = get_all_email_platforms()
    
    # Get platform statistics
    platform_stats = get_platform_statistics()
    
    # Get all available platforms
    platforms = get_all_platforms()
    
    return render_template("email_platforms.html", 
                         email_platforms=email_platforms_data,
                         platform_stats=platform_stats,
                         platforms=platforms)

# API endpoint to add/update email-platform mapping
@app.route("/api/email-platform", methods=["POST"])
def api_add_email_platform():
    if not check_admin_auth():
        return {"error": "Unauthorized"}, 401
    
    data = request.get_json()
    email = data.get("email")
    platform = data.get("platform")
    notes = data.get("notes", "")
    
    if not email or not platform:
        return {"error": "Email and platform are required"}, 400
    
    success = add_email_platform(email, platform, notes)
    if success:
        return {"success": True, "message": f"Email {email} mapped to platform {platform}"}
    else:
        return {"error": "Failed to map email to platform"}, 500

# API endpoint to get email-platform mapping
@app.route("/api/email-platform/<email>")
def api_get_email_platform(email):
    if not check_admin_auth():
        return {"error": "Unauthorized"}, 401
    
    platform_data = get_email_platform(email)
    if platform_data:
        return platform_data
    else:
        return {"error": "Email not found"}, 404

# API endpoint to delete email-platform mapping
@app.route("/api/email-platform/<email>", methods=["DELETE"])
def api_delete_email_platform(email):
    if not check_admin_auth():
        return {"error": "Unauthorized"}, 401
    
    success = delete_email_platform(email)
    if success:
        return {"success": True, "message": f"Email {email} mapping deleted"}
    else:
        return {"error": "Failed to delete email mapping"}, 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)