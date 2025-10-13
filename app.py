from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy import func, extract
from datetime import datetime
import os
import json

# ----------------- Flask App Setup -----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret")  # env variable recommended for production
s = URLSafeTimedSerializer(app.secret_key)

# SQLite DB for Vercel
db_path = os.path.join("/tmp", "app.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ----------------- Flask-Login -----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ----------------- Mail Setup -----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'aigeneratednoreply@gmail.com'
app.config['MAIL_PASSWORD'] = 'npmm ivwa uhri jwwi'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# ----------------- Models -----------------
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

# Create tables
with app.app_context():
    db.create_all()

# ----------------- Login Manager -----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------- Routes -----------------

@app.route("/")
def index():
    return render_template("index.html")

# Signup
@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']

        if User.query.filter((User.username==username)|(User.email==email)).first():
            flash("Username or email already exists!")
            return redirect(url_for('login'))

        hashed = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed, user_type=user_type)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! Please login.")
        return redirect(url_for('login'))

    return render_template("signup.html")

# Login
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method=='POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('welcome'))
        flash("Invalid username or password!")
    return render_template("login.html")

# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully")
    return redirect(url_for("index"))

# ----------------- Dashboard -----------------
@app.route("/welcome", methods=['GET','POST'])
@login_required
def welcome():
    user_type = current_user.user_type
    if user_type=="student":
        total_exp = db.session.query(func.sum(Expenses.amount)).filter_by(user_id=current_user.id).scalar() or 0
        total_pocket = db.session.query(func.sum(PocketMoney.amount)).filter_by(user_id=current_user.id).scalar() or 0
        remaining = total_pocket - total_exp
        return render_template("student.html", username=current_user.username,
                               total_pocket=total_pocket, total_expenses=total_exp, remaining=remaining)

    elif user_type=="individual":
        selected_month = request.form.get('month', type=int)
        selected_year = request.form.get('year', type=int)
        category_filter = request.form.get('category')

        if selected_month and selected_year:
            total_spent = db.session.query(func.sum(Savings.amount))\
                .filter_by(user_id=current_user.id)\
                .filter(extract('month', Savings.date)==selected_month)\
                .filter(extract('year', Savings.date)==selected_year)\
                .scalar() or 0
            budget_entry = Budget.query.filter_by(user_id=current_user.id, month=selected_month, year=selected_year).first()
            budget_amount = budget_entry.amount if budget_entry else 0
        else:
            total_spent = db.session.query(func.sum(Savings.amount)).filter_by(user_id=current_user.id).scalar() or 0
            budget_amount = db.session.query(func.sum(Budget.amount)).filter_by(user_id=current_user.id).scalar() or 0

        remaining = budget_amount - total_spent

        cat_rows = db.session.query(Savings.category, func.sum(Savings.amount))\
            .filter_by(user_id=current_user.id)
        if category_filter:
            cat_rows = cat_rows.filter(Savings.category==category_filter)
        cat_rows = cat_rows.group_by(Savings.category).all()
        categories = [c for c,_ in cat_rows] if cat_rows else []
        category_values = [s for _,s in cat_rows] if cat_rows else []

        color_map = {
            "Food": "rgba(255, 99, 132, 0.6)",
            "Transport": "rgba(54, 162, 235, 0.6)",
            "Entertainment": "rgba(255, 206, 86, 0.6)",
            "Bills": "rgba(75, 192, 192, 0.6)",
            "Other": "rgba(255, 159, 64, 0.6)"
        }
        category_colors = [color_map.get(c,"rgba(200,200,200,0.6)") for c in categories]

        return render_template("individual.html",
                               username=current_user.username,
                               total_pocket=budget_amount,
                               total_expenses=total_spent,
                               remaining=remaining,
                               selected_month=selected_month,
                               selected_year=selected_year,
                               category=categories,
                               category_values=category_values,
                               category_colors=category_colors)

    elif user_type=="freelancer":
        # Freelancer dashboard logic (similar to above)
        pass

    else:
        return f"Unknown role: {user_type}", 400

# ----------------- Run App -----------------
if __name__=="__main__":
    app.run(debug=True)
