from flask import Flask, render_template, request, redirect, url_for, abort,  flash
import sqlite3
import bcrypt
import html

from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField, PasswordField
from wtforms.validators import DataRequired, NumberRange, EqualTo
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import validate_csrf, CSRFError

class TransferForm(FlaskForm):
    recipient = StringField('Recipient', validators=[DataRequired()])
    amount = DecimalField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('Transfer')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CommentForm(FlaskForm):
    comment = StringField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post Comment')

app = Flask(__name__)
app.secret_key = 'your-very-secret-key'
csrf = CSRFProtect(app)
# Insecure database connection (no parameterization)
def get_user_from_db(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    conn.close()
    return user

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    form = CommentForm()  # Instantiate the form object
    comments = []

    if form.validate_on_submit():  # Checks for POST request and validates the form
        user_comment = form.comment.data  # Get the comment from the form

        sanitized_comment = html.escape(user_comment)
        # Save sanitized comment to a file
        with open('comments.txt', 'a') as f:
            f.write(sanitized_comment + "\n")

    # Read all comments from the file
    with open('comments.txt', 'r') as f:
        comments = f.readlines()

    # Escape comments when rendering to prevent XSS
    escaped_comments = [html.escape(comment) for comment in comments]
    return render_template('comments.html', comments=escaped_comments, form=form)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    form = TransferForm()
    success = False

    if request.method == 'POST':
        try:
            # Manually validate the CSRF token
            validate_csrf(request.form.get('csrf_token'))
        except CSRFError:
            abort(400, description="CSRF token verification failed!")

        if form.validate_on_submit():
            recipient = form.recipient.data
            amount = form.amount.data

            # Log the transaction securely
            with open('transactions.txt', 'a') as f:
                f.write(f"Transfer to: {recipient}, Amount: {amount}\n")

            success = True
            return redirect(url_for('transfer'))

    return render_template('transfer.html', form=form, success=success)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Fetch user data from the database
        user = get_user_from_db(username)

        if user:
            stored_hash = user[2]  

            # Compare the stored hash with the password provided by the user
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                return redirect('/')  # Redirect to home page on successful login
            else:
                flash('Invalid credentials', 'error')  # Flash an error message
                return redirect(url_for('login'))

        else:
            flash('Invalid credentials', 'error')  # Flash an error message for invalid username
            return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data

        # Validate if passwords match
        if password != confirm_password:
            return 'Passwords do not match!', 400

        # Check if username already exists
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return 'Username already taken!', 400

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert the new user into the database
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))  # Redirect to login after successful registration

    return render_template('register.html', form=form)  # Pass the form to the template for rendering



        

if __name__ == "__main__":
    app.run(debug=True)
