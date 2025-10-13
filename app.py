from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user
from sqlalchemy import func, extract
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from datetime import datetime
import secrets
import os
import json

# ----------------- APP CONFIG -----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
s = URLSafeTimedSerializer(app.secret_key)

# SQLite database in /tmp for Vercel
db_path = "/tmp/app.db"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

with app.app_context():
    db.create_all()


# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# ----------------- DATABASE MODELS -----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)

class Expenses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

class PocketMoney(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=datetime.utcnow)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

class Savings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    month = db.Column(db.Integer)
    year = db.Column(db.Integer)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=True)

class Free(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# ----------------- USER LOADER -----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------- ROUTES -----------------
@app.route("/")
def index():
    return render_template("index.html")

# Signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']

        if User.query.filter((User.username==username)|(User.email==email)).first():
            flash("Username or email already exists!")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed_password, user_type=user_type)
        db.session.add(user)
        db.session.commit()
        flash("Signup successful! Please login.")
        return redirect(url_for('login'))
    return render_template("signup.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('welcome'))
        flash("Invalid credentials.")
    return render_template("login.html")

# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

# Forget Password
@app.route('/forgetpassword', methods=['GET','POST'])
def forgetpassword():
    if request.method=='POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='email-reset')
            reset_link = url_for('updatepassword', token=token, _external=True)
            msg = Message('Reset Your Password', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f'Click the link to reset password: {reset_link}'
            mail.send(msg)
            flash("Reset link sent to your email.", "success")
        else:
            flash("Email not found.", "danger")
    return render_template("forgetpassword.html")

# Update Password
@app.route('/updatepassword/<token>', methods=['GET','POST'])
def updatepassword(token):
    try:
        email = s.loads(token, salt='email-reset', max_age=1200)
    except SignatureExpired:
        flash("Token expired. Try again.", "danger")
        return redirect(url_for('forgetpassword'))

    if request.method=='POST':
        new_password = request.form['password']
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Password updated successfully!", "success")
        return redirect(url_for('login'))
    return render_template("updatepassword.html")

# ----------------- WELCOME DASHBOARD -----------------
@app.route('/welcome', methods=['GET','POST'])
@login_required
def welcome():
    user_type = current_user.user_type
    if user_type=="student":
        total_exp = db.session.query(func.sum(Expenses.amount)).filter_by(user_id=current_user.id).scalar() or 0
        total_pocket = db.session.query(func.sum(PocketMoney.amount)).filter_by(user_id=current_user.id).scalar() or 0
        remaining = total_pocket - total_exp
        return render_template("student.html", username=current_user.username, total_pocket=total_pocket, total_expenses=total_exp, remaining=remaining)
    elif user_type=="individual":
        # simplified individual dashboard
        total_spent = db.session.query(func.sum(Savings.amount)).filter_by(user_id=current_user.id).scalar() or 0
        budget = db.session.query(func.sum(Budget.amount)).filter_by(user_id=current_user.id).scalar() or 0
        remaining = budget - total_spent
        return render_template("individual.html", username=current_user.username, total_pocket=budget, total_expenses=total_spent, remaining=remaining)
    elif user_type=="freelancer":
        total_income = db.session.query(func.sum(Income.amount)).filter_by(user_id=current_user.id).scalar() or 0
        total_expense = db.session.query(func.sum(Free.amount)).filter_by(user_id=current_user.id).scalar() or 0
        remaining = total_income - total_expense
        return render_template("freelance.html", total_income=total_income, total_expense=total_expense, remaining=remaining)
    else:
        return "Unknown role", 400

# ----------------- RUN APP -----------------
if __name__ == "__main__":
    app.run(debug=True)
