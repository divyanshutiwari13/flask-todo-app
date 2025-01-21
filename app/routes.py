from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, bcrypt
from app.models import User, TodoItem

main = Blueprint('main', __name__)

# Redirect root to signup
@main.route('/')
def home():
    return redirect(url_for('main.signup'))

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    # Prevent already logged-in users from signing up again
    if current_user.is_authenticated:
        return redirect(url_for('main.todo'))
    
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('main.signup'))

        # Check if email is already registered
        if User.query.filter_by(email=email).first():
            flash('Email is already registered. Please login.', 'warning')
            return redirect(url_for('main.login'))

        # Hash the password and save the user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Successfully signed up! Please login.', 'success')
        return redirect(url_for('main.login'))

    return render_template('signup.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    # Prevent already logged-in users from accessing the login page
    if current_user.is_authenticated:
        return redirect(url_for('main.todo'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Successfully logged in!', 'success')
            return redirect(url_for('main.todo'))
        else:
            flash('Login failed. Check email and password.', 'danger')
    return render_template('login.html')

@main.route('/todo', methods=['GET', 'POST'])
@login_required  # Only logged-in users can access
def todo():
    if request.method == 'POST':
        content = request.form['content']
        todo_item = TodoItem(content=content, user_id=current_user.id)
        db.session.add(todo_item)
        db.session.commit()
        return redirect(url_for('main.todo'))
    
    todos = TodoItem.query.filter_by(user_id=current_user.id).all()
    return render_template('todo.html', todos=todos)

@main.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('main.login'))
