from flask import Flask, render_template, redirect, url_for, request, flash
from config import Config
from models import db, User, AuditLog, Transaction, ControlAlert
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
from functools import wraps
import random

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()


# ================= ROLE DECORATOR =================
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                return "Access Denied", 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ================= ROUTES =================

@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for("register"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

        # First user = Admin
        if User.query.count() == 0:
            role = "Admin"
        else:
            # Safely get role, default to Staff if missing
            role = request.form.get("role") or "Staff"

        new_user = User(username=username, password=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)

            log = AuditLog(
                user_id=user.id,
                action="Logged in",
                timestamp=datetime.utcnow()
            )
            db.session.add(log)
            db.session.commit()

            return redirect(url_for("dashboard"))
        else:
            flash("Invalid login credentials")

    return render_template("login.html")


# ================= DASHBOARD =================
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


# ================= CREATE TRANSACTION =================
@app.route("/create-transaction", methods=["GET", "POST"])
@login_required
@role_required("Staff")
def create_transaction():
    if request.method == "POST":
        amount = float(request.form.get("amount"))

        transaction = Transaction(
            created_by=current_user.id,
            amount=amount,
            status="Pending"
        )
        db.session.add(transaction)

        log = AuditLog(
            user_id=current_user.id,
            action=f"Created transaction of {amount}",
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

        return "Transaction Created"

    return render_template("create_transaction.html")


# ================= APPROVE TRANSACTION =================
@app.route("/approve/<int:transaction_id>")
@login_required
@role_required("Manager")
def approve_transaction(transaction_id):

    transaction = Transaction.query.get_or_404(transaction_id)

    # Fraud rule: flag suspicious high-value transactions
    if transaction.amount > 50000:
        alert = ControlAlert(
            transaction_id=transaction.id,
            alert_type="Suspicious Transaction",
            description="Transaction unusually high"
        )
        db.session.add(alert)

    # Control rule: Manager cannot approve above 10000
    if transaction.amount > 10000:
        alert = ControlAlert(
            transaction_id=transaction.id,
            alert_type="Approval Limit Exceeded",
            description="Transaction exceeds manager approval limit"
        )
        db.session.add(alert)
        db.session.commit()
        return "Approval Denied - Limit Exceeded"

    transaction.status = "Approved"
    transaction.approved_by = current_user.id

    log = AuditLog(
        user_id=current_user.id,
        action=f"Approved transaction {transaction.id}",
        timestamp=datetime.utcnow()
    )
    db.session.add(log)

    db.session.commit()
    return "Transaction Approved"


# ================= LOGOUT =================
@app.route("/logout")
@login_required
def logout():
    log = AuditLog(
        user_id=current_user.id,
        action="Logged out",
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()

    logout_user()
    return redirect(url_for("login"))


# ================= VIEW ALERTS =================
@app.route("/alerts")
@login_required
@role_required("Manager")
def view_alerts():
    alerts = ControlAlert.query.all()
    return render_template("alerts.html", alerts=alerts)


# ================= GENERATE TEST DATA =================
@app.route("/generate-test-data")
@login_required
@role_required("Admin")
def generate_test_data():
    for i in range(200):
        amount = random.randint(1000, 100000)
        transaction = Transaction(
            created_by=current_user.id,
            amount=amount,
            status="Pending"
        )
        db.session.add(transaction)
    db.session.commit()
    return "200 Transactions Generated"


# ================= STATISTICS VIEW =================
@app.route("/stats")
@login_required
@role_required("Admin")
def stats():
    total = Transaction.query.count()
    fraud = Transaction.query.filter(Transaction.amount > 50000).count()
    alerts = ControlAlert.query.count()
    return f"""
    Total Transactions: {total}<br>
    Fraud Attempts: {fraud}<br>
    Alerts Generated: {alerts}
    """


if __name__ == "__main__":
    app.run(debug=True)