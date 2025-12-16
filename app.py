from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_session import Session
from imapclient import IMAPClient
import email

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # غيّرها لمفتاح آمن
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

IMAP_SERVER = 'mail.bltnm.store'
IMAP_PORT = 993

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email_user = request.form.get("email")
        password = request.form.get("password")

        try:
            with IMAPClient(IMAP_SERVER, ssl=True, port=IMAP_PORT) as client:
                client.login(email_user, password)
            session['email_user'] = email_user
            session['password'] = password
            return redirect(url_for("inbox"))
        except Exception as e:
            flash("Authentication failed! Check your email or password.", "danger")
            return render_template("login.html")
    return render_template("login.html")

@app.route("/inbox")
def inbox():
    if 'email_user' not in session:
        return redirect(url_for("login"))

    email_user = session['email_user']
    password = session['password']

    messages_list = []

    try:
        with IMAPClient(IMAP_SERVER, ssl=True, port=IMAP_PORT) as client:
            client.login(email_user, password)
            client.select_folder("INBOX")
            messages = client.search(['ALL'])
            for uid, message_data in client.fetch(messages, ['RFC822']).items():
                msg = email.message_from_bytes(message_data[b'RFC822'])
                messages_list.append({
                    'from': msg['From'],
                    'subject': msg['Subject']
                })
    except Exception as e:
        flash("Failed to fetch emails.", "danger")
        messages_list = []

    return render_template("inbox.html", messages=messages_list, email=email_user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
