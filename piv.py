from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Generate an encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Initialize storage
stored_passwords = []
stored_notes = []
stored_payments = []

master_password_hash = None
user_pin_hash = None

@app.route("/")
def home():
    if not session.get("logged_in"):
        return render_template("home.html")
    return redirect(url_for("dashboard"))

@app.route("/create-master-password", methods=["POST"])
def create_master_password():
    global master_password_hash
    password = request.form["password"]
    if len(password) < 8:
        flash("Password must be at least 8 characters long.")
        return redirect(url_for("home"))
    master_password_hash = generate_password_hash(password)
    session["logged_in"] = True
    flash("Master password created! Now set up a 4-digit PIN.")
    return redirect(url_for("create_pin"))

@app.route("/create-pin", methods=["GET", "POST"])
def create_pin():
    global user_pin_hash
    if request.method == "POST":
        pin = request.form["pin"]
        if len(pin) == 4 and pin.isdigit():
            user_pin_hash = generate_password_hash(pin)
            flash("PIN created successfully! You can now access your data.")
            return redirect(url_for("dashboard"))
        else:
            flash("PIN must be exactly 4 digits.")
    return render_template("create_pin.html")


@app.route("/login", methods=["POST"])
def login():
    global master_password_hash
    if master_password_hash is None:
        flash("Master password has not been set. Please create one first.")
        return redirect(url_for("home"))
    password = request.form["password"]
    if check_password_hash(master_password_hash, password):
        session["logged_in"] = True
        flash("Logged in successfully!")
        return redirect(url_for("dashboard"))
    flash("Invalid password. Please try again.")
    return redirect(url_for("home"))

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("home"))
    return render_template("dashboard.html")

@app.route("/save-password", methods=["POST"])
def save_password():
    global stored_passwords
    tag = request.form["password-tag"]
    new_password = request.form["new-password"]
    encrypted_password = cipher_suite.encrypt(new_password.encode())
    stored_passwords.append((tag, encrypted_password))
    flash(f"Password for '{tag}' saved!")
    return redirect(url_for("dashboard"))

@app.route("/save-note", methods=["POST"])
def save_note():
    global stored_notes
    title = request.form.get("note-title")
    content = request.form.get("note-content")

    if title and content:
        encrypted_content = cipher_suite.encrypt(content.encode())
        stored_notes.append((title, encrypted_content))
        flash(f"Note '{title}' saved successfully!")
    else:
        flash("Both title and content are required to save a note.")
    return redirect(url_for("dashboard"))

@app.route("/save-payment", methods=["POST"])
def save_payment():
    global stored_payments
    card_number = request.form.get("card-number")
    cardholder_name = request.form.get("cardholder-name")

    if card_number and cardholder_name:
        payment_details = f"{card_number},{cardholder_name}"
        encrypted_payment = cipher_suite.encrypt(payment_details.encode())
        stored_payments.append(encrypted_payment)
        flash(f"Payment details for '{cardholder_name}' saved successfully!")
    else:
        flash("Both card number and cardholder name are required to save payment details.")
    return redirect(url_for("dashboard"))


@app.route("/view-passwords", methods=["GET", "POST"])
def view_passwords():
    global user_pin_hash, stored_passwords
    if "pin_verified" not in session:
        if request.method == "POST":
            pin = request.form["pin"]
            if check_password_hash(user_pin_hash, pin):
                session["pin_verified"] = True
                flash("PIN verified! You can now view your passwords.")
            else:
                flash("Invalid PIN. Please try again.")
                return redirect(url_for("view_passwords"))
        else:
            return render_template("verify_pin.html", next_page="view_passwords")

    # Handle search query
    query = request.args.get("query", "").strip().lower()
    if query:
        filtered_passwords = [
            (tag, cipher_suite.decrypt(password).decode())
            for tag, password in stored_passwords if query in tag.lower()
        ]
    else:
        filtered_passwords = [
            (tag, cipher_suite.decrypt(password).decode())
            for tag, password in stored_passwords
        ]
    return render_template("view_passwords.html", passwords=filtered_passwords)

@app.route("/view-notes", methods=["GET", "POST"])
def view_notes():
    global user_pin_hash, stored_notes
    if "pin_verified" not in session:
        if request.method == "POST":
            pin = request.form["pin"]
            if check_password_hash(user_pin_hash, pin):
                session["pin_verified"] = True
                flash("PIN verified! You can now view your notes.")
            else:
                flash("Invalid PIN. Please try again.")
                return redirect(url_for("view_notes"))
        else:
            return render_template("verify_pin.html", next_page="view_notes")

    # Handle search query
    query = request.args.get("query", "").strip().lower()
    if query:
        filtered_notes = [
            (title, cipher_suite.decrypt(content).decode())
            for title, content in stored_notes if query in title.lower()
        ]
    else:
        filtered_notes = [
            (title, cipher_suite.decrypt(content).decode())
            for title, content in stored_notes
        ]
    return render_template("view_notes.html", notes=filtered_notes)

@app.route("/view-payments", methods=["GET", "POST"])
def view_payments():
    global user_pin_hash, stored_payments
    if "pin_verified" not in session:
        if request.method == "POST":
            pin = request.form["pin"]
            if check_password_hash(user_pin_hash, pin):
                session["pin_verified"] = True
                flash("PIN verified! You can now view your payments.")
            else:
                flash("Invalid PIN. Please try again.")
                return redirect(url_for("view_payments"))
        else:
            return render_template("verify_pin.html", next_page="view_payments")

    # Handle search query
    query = request.args.get("query", "").strip().lower()
    if query:
        filtered_payments = [
            cipher_suite.decrypt(payment).decode()
            for payment in stored_payments if query in cipher_suite.decrypt(payment).decode().split(",")[1].lower()
        ]
    else:
        filtered_payments = [
            cipher_suite.decrypt(payment).decode()
            for payment in stored_payments
        ]
    return render_template("view_payments.html", payments=filtered_payments)





@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out!")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
