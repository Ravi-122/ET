from flask import Flask, render_template, request, redirect, url_for, session, flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_required, login_user,current_user
from sqlalchemy import func,extract
from itsdangerous import URLSafeTimedSerializer,SignatureExpired
from datetime import datetime,date
from decimal import Decimal
import random
import hashlib
import sqlite3
import secrets
import os
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session management
s = URLSafeTimedSerializer(app.secret_key)

# /tmp is writable on Vercel
db_path = os.path.join("/tmp", "app.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()       # ✅ separate object
login_manager.init_app(app)          # attach to app
login_manager.login_view = "login"   # route name to redirect if not logged in


# User model
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
# Creating Expenses database
class expenses(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(50),nullable=False)
    amount=db.Column(db.Float(100,4),nullable=False)
    date=db.Column(db.DateTime,default=db.func.current_timestamp())
    user_id=db.Column(db.Integer,db.ForeignKey("user.id",name="fk_expenses_user_id"), nullable=False)
#Creating Student Pocket money table
class pocketmoney(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=datetime.utcnow)
    amount=db.Column(db.Float(100,4),nullable=False)
    user_id=db.Column(db.Integer,db.ForeignKey("user.id",name="fk_pocketmoney_user_id"),nullable=False)
#creating For Individual money table
class savings(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    amount=db.Column(db.Float(100,4),nullable=False)
    category = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, default=datetime.utcnow)
    user_id=db.Column(db.Integer,db.ForeignKey("user.id",name="fk_savings_user_id"),nullable=False)
class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    month = db.Column(db.Integer)   # 1-12
    year = db.Column(db.Integer)
    amount = db.Column(db.Float(100,4), nullable=False)
    category = db.Column(db.String(100), nullable=True)  # Optional per category


#reating for the frelancing
class free(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, default=datetime.utcnow)
    user_id=db.Column(db.Integer,db.ForeignKey("user.id",name="fk_free_user_id"),nullable=False)
class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount=db.Column(db.Float(100,4),nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id",name="fk_Income_user_id"),nullable=False)  # optional


#Email Config for password reset
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']= 465
app.config['MAIL_USERNAME']='aigeneratednoreply@gmail.com'
app.config['MAIL_PASSWORD']='npmm ivwa uhri jwwi'
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
mail=Mail(app)

# Home route
@app.route("/")
def index():
    return render_template("index.html")

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']

        # Check if user already exists
        existing_user = User.query.filter((User.username==username) | (User.email==email)).first()
        if existing_user:
            flash("Username or email already exists! Please login.")
            return redirect(url_for('login'))

        # Hash password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create new user
        new_user = User(username=username, email=email, password=hashed_password, user_type=user_type)
        db.session.add(new_user)
        db.session.commit()
        return render_template('login.html')
    return render_template('signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)  # ✅ This tells Flask-Login that the user is authenticated
            print("DEBUG: logged in user_type =", user.user_type)
            return redirect(url_for('welcome'))

        else:
            flash("Invalid username or password!")
    return render_template('login.html')
#Forget Password
@app.route('/forgetpassword', methods=['GET', 'POST'])
def forgetpassword():
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute("SELECT * FROM user WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user:
            token = s.dumps(email, salt='email-reset')
            reset_link = url_for('updatepassword', token=token, _external=True)
            message = Message(
                'Reset Your Password',
                sender='aigeneratednoreply@gmail.com',
                recipients=[email]
            )
            message.body = f'Click this link to reset your password: {reset_link}. If not you, ignore this email.'
            mail.send(message)
            flash('A link has been sent to your email.', 'success')
            return render_template('login.html')
        else:
            flash('Email not found. Please check your email or sign up first.', 'danger')
    return render_template('forgetpassword.html')

#Link generation after forget [asswprd to update it
@app.route('/updatepassword/<token>',methods=['GET','POST'])
def updatepassword(token):
    try:
        email=s.loads(token,salt='email-reset',max_age=1200)
    except SignatureExpired:
        flash('the link is expired try again')
        return redirect(url_for('forgetpassword'))
    if request.method=='POST':
        new_password=request.form['password']
        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
        conn=sqlite3.connect('app.db')
        c=conn.cursor()
        c.execute('update user SET password=? where email=?',(hashed_password, email))
        conn.commit()
        conn.close()
        flash('Your password has been updated successfully!', 'success')
        return render_template('login.html')
    return render_template('updatepassword.html')

# Welcome route


# Welcome route
@app.route('/welcome', methods=['GET', 'POST'])
@login_required
def welcome():
    user_type = current_user.user_type

    # -------- Student --------
    if user_type == "student":
        total_expenses = db.session.query(func.sum(expenses.amount))\
            .filter_by(user_id=current_user.id).scalar() or 0
        total_pocket = db.session.query(func.sum(pocketmoney.amount))\
            .filter_by(user_id=current_user.id).scalar() or 0
        remaining = total_pocket - total_expenses

        return render_template(
            "student.html",
            username=current_user.username,
            total_pocket=total_pocket,
            total_expenses=total_expenses,
            remaining=remaining
        )

    # -------- Individual --------
    elif user_type == "individual":
        selected_month = request.form.get('month', type=int)
        selected_year = request.form.get('year', type=int)
        category_filter = request.form.get('category')

        if selected_month and selected_year:
            total_spent = db.session.query(func.sum(savings.amount))\
                .filter_by(user_id=current_user.id)\
                .filter(extract('month', savings.date) == selected_month)\
                .filter(extract('year', savings.date) == selected_year)\
                .scalar() or 0

            budget_entry = Budget.query.filter_by(
                user_id=current_user.id,
                month=selected_month,
                year=selected_year
            ).first()
            budget_amount = budget_entry.amount if budget_entry else 0
        else:
            total_spent = db.session.query(func.sum(savings.amount))\
                .filter_by(user_id=current_user.id).scalar() or 0
            budget_amount = db.session.query(func.sum(Budget.amount))\
                .filter_by(user_id=current_user.id).scalar() or 0

        remaining = budget_amount - total_spent

        # Category-wise expenses
        cat_q = db.session.query(savings.category, func.sum(savings.amount))\
            .filter_by(user_id=current_user.id)
        if category_filter:
            cat_q = cat_q.filter(savings.category == category_filter)
        cat_rows = cat_q.group_by(savings.category).all()

        category = [c for c,_ in cat_rows] if cat_rows else []
        category_values = [s for _,s in cat_rows] if cat_rows else []

        # Optional color mapping
        color_map = {
            "Food": "rgba(255, 99, 132, 0.6)",
            "Transport": "rgba(54, 162, 235, 0.6)",
            "Entertainment": "rgba(255, 206, 86, 0.6)",
            "Bills": "rgba(75, 192, 192, 0.6)",
            "Other": "rgba(255, 159, 64, 0.6)"
        }
        category_colors = [color_map.get(c, "rgba(200, 200, 200, 0.6)") for c in category]

        return render_template(
            "individual.html",
            username=current_user.username,
            total_pocket=budget_amount,
            total_expenses=total_spent,
            remaining=remaining,
            selected_month=selected_month,
            selected_year=selected_year,
            category=category,
            category_values=category_values,
            category_colors=category_colors
        )

    # -------- Freelancer --------
    elif user_type == "freelancer":
        total_income = total_expense = remaining = entered_income = 0
        start_date = end_date = None
        category_filter = request.form.get('category')

        if request.method == 'POST':
            start_date_input = request.form.get('start_date')
            end_date_input = request.form.get('end_date')
            entered_income_input = request.form.get('income')

            try:
                entered_income = float(entered_income_input) if entered_income_input else 0
            except ValueError:
                flash("Invalid income entered!", "error")

            try:
                if start_date_input and end_date_input:
                    start_date = datetime.strptime(start_date_input, '%Y-%m-%d').date()
                    end_date = datetime.strptime(end_date_input, '%Y-%m-%d').date()
            except ValueError:
                flash("Invalid date format!", "error")
                start_date = end_date = None

        # Total income
        income_query = db.session.query(func.sum(Income.amount))\
            .filter(Income.user_id == current_user.id)
        if start_date and end_date:
            income_query = income_query.filter(Income.date >= start_date, Income.date <= end_date)
        total_income = float(income_query.scalar() or 0)
        if total_income == 0 and entered_income:
            total_income = entered_income

        # Total expenses
        expense_query = db.session.query(func.sum(free.amount))\
            .filter(free.user_id == current_user.id)
        if start_date and end_date:
            expense_query = expense_query.filter(free.date >= start_date, free.date <= end_date)
        total_expense = float(expense_query.scalar() or 0)
        remaining = total_income - total_expense

        # Category-wise expenses
        cat_q = db.session.query(free.category, func.sum(free.amount))\
            .filter(free.user_id == current_user.id)
        if start_date and end_date:
            cat_q = cat_q.filter(free.date >= start_date, free.date <= end_date)
        if category_filter:
            cat_q = cat_q.filter(free.category == category_filter)
        cat_rows = cat_q.group_by(free.category).all()

        category = [c for c,_ in cat_rows] if cat_rows else []
        category_values = [s for _,s in cat_rows] if cat_rows else []

        # Color mapping
        color_map = {
            "Design": "rgba(255, 99, 132, 0.6)",
            "Development": "rgba(54, 162, 235, 0.6)",
            "Writing": "rgba(255, 206, 86, 0.6)",
            "Consulting": "rgba(75, 192, 192, 0.6)",
            "Other": "rgba(255, 159, 64, 0.6)"
        }
        category_colors = [color_map.get(c, "rgba(200, 200, 200, 0.6)") for c in category]

        return render_template(
            "freelance.html",
            total_income=total_income,
            total_expense=total_expense,
            remaining=remaining,
            start_date=start_date,
            end_date=end_date,
            entered_income=entered_income,
            category=category,
            category_values=category_values,
            category_colors=category_colors
        )

    # -------- Unknown user type --------
    else:
        return f"Unknown role: {user_type}", 400




#Profile data
@app.route('/profile')
@login_required
def profile():
    info={
        "username":current_user.username,
        "email":current_user.email,
        "user_type":current_user.user_type

    }
    return render_template('profile.html',user=info)

    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Add Expense
@app.route("/addexpenses", methods=["GET", "POST"])
@login_required
def addexpenses():
    if request.method == "POST":
        title = request.form["title"]
        amount = request.form["amount"]
        new_expense = expenses(title=title, amount=amount, user_id=current_user.id)
        db.session.add(new_expense)
        db.session.commit()
        return redirect(url_for("my_expenses"))
    return render_template("addexpenses.html")






# View Expenses
@app.route("/my_expenses")
@login_required
def my_expenses():
    expense = expenses.query.filter_by(user_id=current_user.id).all()
    total_amount = db.session.query(func.sum(expenses.amount))\
        .filter(expenses.user_id == current_user.id).scalar()
    if total_amount is None:
        total_amount = 0
    return render_template("my_expenses.html", expenses=expense,total_amount=total_amount)

@app.route('/pocket_money', methods=['GET', 'POST'])
@login_required
def pocket_money():
    remaining = None
    message = ""

    if request.method == 'POST':
        try:
            income = float(request.form['income'])

            # Check if user already has a pocket money entry for today
            pocket = pocketmoney.query.filter_by(user_id=current_user.id).first()
            if pocket:
                pocket.amount = income
            else:
                pocket = pocketmoney(user_id=current_user.id, amount=income, date=datetime.utcnow())
                db.session.add(pocket)
            
            db.session.commit()

            # Calculate total expenses
            total_expenses = db.session.query(func.sum(expenses.amount))\
                .filter(expenses.user_id == current_user.id).scalar() or 0

            # Calculate total pocket money
            total_pocket = db.session.query(func.sum(pocketmoney.amount))\
                .filter(pocketmoney.amount == current_user.id).scalar() or 0

            remaining = total_pocket - total_expenses
            message = f"Your remaining pocket money is {remaining:.2f}"

        except ValueError:
            message = "Please enter a valid number."

    return render_template('pocket_money.html', remaining=remaining, message=message)
# Delete Expense
@app.route("/delete_expense/<int:expense_id>")
@login_required
def delete_expense(expense_id):
    expense = expenses.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash("You cannot delete this expense!")
        return redirect(url_for('my_expenses'))
    db.session.delete(expense)
    db.session.commit()
    flash("Expense deleted successfully!")
    return redirect(url_for('my_expenses'))

#Update or edit
@app.route("/edit_expense/<int:expense_id>", methods=["GET", "POST"])
@login_required
def edit_expense(expense_id):
    expense = expenses.query.get_or_404(expense_id)

    if expense.user_id != current_user.id:
        flash("You cannot edit this expense!", "danger")
        return redirect(url_for('my_expenses'))

    if request.method == "POST":
        expense.amount = float(request.form['amount'])
        expense.title = request.form['title']

        # ✅ Convert the date string to a Python date object
        date_str = request.form['date']
        expense.date = datetime.strptime(date_str, "%Y-%m-%d").date()

        db.session.commit()
        flash("Expense updated successfully!", "success")
        return redirect(url_for('my_expenses'))

    return render_template("edit.html", expense=expense)





#for freelancer
@app.route('/freeadd', methods=["GET", "POST"])
@login_required
def freeadd():
    if request.method == "POST":
        amount = request.form['amount']
        category = request.form['category']
        date_str = request.form['date']
        if date_str:
            date = datetime.strptime(date_str, '%Y-%m-%d')
        else:
            date = datetime.utcnow() 
        new_expense = free(amount=amount, date=date,category=category, user_id=current_user.id)
        db.session.add(new_expense)
        db.session.commit()
        flash("Freelance expense added successfully!", "success")
        return redirect(url_for("feeview"))

    return render_template("freeadd.html")


@app.route("/feeview")
@login_required
def feeview():
    # Fetch all freelance expense records for the logged-in user
    exp = free.query.filter_by(user_id=current_user.id).order_by(free.date.desc()).all()

    # Calculate the total amount
    total_amount = db.session.query(func.sum(free.amount)) \
        .filter(free.user_id == current_user.id).scalar()

    if total_amount is None:
        total_amount = 0

    return render_template(
        "feeview.html",
        exp=exp,
        total_amount=total_amount
    )
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    total_income = 0
    total_expense = 0
    remaining = 0
    selected_month = None
    selected_year = None

    if request.method == 'POST':
        # ✅ Step 1: Get data from the form safely
        total_income_input = request.form.get('total_income')
        month_input = request.form.get('month')
        year_input = request.form.get('year')

        if total_income_input and month_input and year_input:
            total_income = float(total_income_input)
            selected_month = int(month_input)
            selected_year = int(year_input)

            # ✅ Step 2: Store income in DB for the current user
            new_income = Income(
                month=selected_month,
                year=selected_year,
                amount=total_income,
                user_id=current_user.id   # 👈 ensures it's linked to the logged-in user
            )
            db.session.add(new_income)
            db.session.commit()

            # ✅ Step 3: Calculate total expenses for this user & month/year
            # Filter expenses by user_id, month, and year (not the entire year)
            total_expense = db.session.query(func.sum(free.amount))\
                .filter(
                    free.user_id == current_user.id,
                    func.strftime('%m', free.date) == f"{selected_month:02d}",
                    func.strftime('%Y', free.date) == str(selected_year)
                )\
                .scalar() or 0

            # ✅ Step 4: Calculate remaining balance
            remaining = total_income - total_expense

    return render_template(
        'report.html',
        total_income=total_income,
        total_expense=total_expense,
        remaining=remaining,
        selected_month=selected_month,
        selected_year=selected_year
    )
# 🗑️ DELETE operation
@app.route("/delete_exp/<int:fee_id>")
@login_required
def delete_exp(fee_id):
    s = free.query.get_or_404(fee_id)
    if s.user_id != current_user.id:
        flash("You cannot delete this record.")
        return redirect(url_for('feeview'))
    db.session.delete(s)
    db.session.commit()
    flash("Expense deleted successfully.")
    return redirect(url_for('feeview'))


# ✏️ UPDATE operation
@app.route("/feeupdate/<int:exp_id>", methods=["GET", "POST"])
@login_required
def update(exp_id):
    exp = free.query.get_or_404(exp_id)
    if exp.user_id != current_user.id:
        flash("You cannot edit this record.")
        return redirect(url_for("feeview"))

    if request.method == "POST":
        print(request.form)
        exp.amount = float(request.form['amount'])
        exp.category = request.form['category']
        db.session.commit()
        flash("Expense updated successfully.")
        return redirect(url_for('feeview'))

    return render_template("feeupdate.html", exp=exp)










@app.route('/moneyuse', methods=['GET', 'POST'])
@login_required
def moneyuse():
    remaining = None
    message = ""
    selected_month = None
    selected_year = None

    if request.method == 'POST':
        try:
            income = float(request.form['income'])

            # Get today's date
            today = datetime.utcnow().date()
            selected_month = today.month
            selected_year = today.year

            # Check if user already has a budget entry for this month/year
            pocket = Budget.query.filter_by(
                user_id=current_user.id,
                month=selected_month,
                year=selected_year
            ).first()

            if pocket:
                pocket.amount = income
            else:
                pocket = Budget(
                    user_id=current_user.id,
                    amount=income,
                    month=selected_month,
                    year=selected_year,
                )
                db.session.add(pocket)

            db.session.commit()

            # Calculate total expenses for this month/year
            total_expenses = db.session.query(func.sum(savings.amount))\
                .filter(savings.user_id == current_user.id)\
                .filter(extract('month', savings.date) == selected_month)\
                .filter(extract('year', savings.date) == selected_year)\
                .scalar() or 0

            # Total pocket money for this month/year
            total_pocket = pocket.amount

            # Remaining money
            remaining = total_pocket - total_expenses
            message = f"Your remaining pocket money for {selected_month}/{selected_year} is {remaining:.2f}"

        except ValueError:
            message = "Please enter a valid number."

    return render_template(
        'moneyuse.html',
        remaining=remaining,
        message=message,
        selected_month=selected_month,
        selected_year=selected_year
    )




@app.route('/inadd', methods=["GET", "POST"])
@login_required
def inadd():
    if request.method == "POST":
        amount = request.form['amount']
        category = request.form['category']
        date_str = request.form['date']
        if date_str:
            date = datetime.strptime(date_str, '%Y-%m-%d')
        else:
            date = datetime.utcnow() 
        new_expense = savings(amount=amount, date=date,category=category, user_id=current_user.id)
        db.session.add(new_expense)
        db.session.commit()
        flash("expense added successfully!", "success")
        return redirect(url_for("inexpenses"))

    return render_template("inadd.html")

@app.route("/inexpenses")
@login_required
def inexpenses():
    # Fetch all freelance expense records for the logged-in user
    expenses = savings.query.filter_by(user_id=current_user.id).order_by(savings.date.desc()).all()

    # Calculate the total amount
    total_amount = db.session.query(func.sum(savings.amount)) \
        .filter(savings.user_id == current_user.id).scalar()

    if total_amount is None:
        total_amount = 0
    return render_template(
        "inexpenses.html",
        expenses=expenses,
        total_amount=total_amount
    )
@app.route("/delete_inexpense/<int:expenses_id>")
@login_required
def delete_inexpense(expenses_id):
    # Fetch the expense record or return 404
    expenses = savings.query.get_or_404(expenses_id)

    # Ensure the current user owns this record
    if expenses.user_id != current_user.id:
        flash("You cannot delete this expense!", "danger")
        return redirect(url_for('inexpenses'))

    db.session.delete(expenses)
    db.session.commit()
    flash("Expense deleted successfully!", "success")
    return redirect(url_for('inexpenses'))

@app.route("/inupdate/<int:up_id>", methods=["GET", "POST"])
@login_required
def inupdate(up_id):
    expense = savings.query.get_or_404(up_id)  # Fetch the record
    if expense.user_id != current_user.id:
        flash("You cannot edit this expense!", "danger")
        return redirect(url_for('inexpenses'))

    if request.method == "POST":
        expense.amount = float(request.form['amount'])
        expense.category = request.form['category']
        db.session.commit()  # Proper indentation
        flash("Expense updated successfully!", "success")
        return redirect(url_for('inexpenses'))

    return render_template("inedit.html", expense=expense)  # Pass correct variable

@app.route('/inchart')
@login_required
def inchart():

    # ----- Category distribution -----
    category_data = db.session.query(
        savings.category, func.sum(savings.amount)
    ).filter_by(user_id=current_user.id).group_by(savings.category).all()

    categories = [row[0] for row in category_data]
    category_totals = [float(row[1]) if row[1] is not None else 0 for row in category_data]  # <-- Convert to float

    # Convert to JSON strings

    categories_json = json.dumps(categories)
    category_totals_json = json.dumps([float(x) for x in category_totals])

    return render_template(
        "inchart.html",

        categories_json=categories_json,
        category_totals_json=category_totals_json
    )
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
