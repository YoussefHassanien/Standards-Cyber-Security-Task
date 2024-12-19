from flask import Flask, render_template, request, redirect, url_for, abort
import sqlite3
import bcrypt
import html

from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField
from wtforms.validators import DataRequired, NumberRange
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import validate_csrf, CSRFError

class TransferForm(FlaskForm):
    recipient = StringField('Recipient', validators=[DataRequired()])
    amount = DecimalField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('Transfer')

app = Flask(__name__)
app.secret_key = 'your-very-secret-key'
csrf = CSRFProtect(app)
# Insecure database connection (no parameterization)
def get_user_from_db(username, password):
    # TODO: Replace this insecure query with parameterized SQL to prevent SQL Injection
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username,password,))
    user = cursor.fetchone()
    conn.close()
    return user

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    comments = []
    if request.method == 'POST':
        user_comment = request.form['comment']

        sanitized_comment = html.escape(user_comment)
        # TODO: Sanitize user input before saving it to prevent XSS
        with open('comments.txt', 'a') as f:
            f.write(sanitized_comment + "\n")  # Save comment to a file (Unsanitized input)
        
    # Read all comments
    with open('comments.txt', 'r') as f:
        comments = f.readlines()
    
    # TODO: Escape comments when rendering to prevent XSS
    escaped_comments = [html.escape(comment) for comment in comments]
    return render_template('comments.html', comments=escaped_comments)

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecure login logic (No hashing or validation)
        # TODO: Use secure password hashing to store and verify passwords
        # TODO: Validate user input to prevent SQL Injection
        user = get_user_from_db(username, password)
        print(user)
        if user:  # Plaintext password comparison (No hashing)
            # TODO: Replace with secure password validation using hashed passwords
            return redirect('/')
        else:
            return 'Invalid credentials!', 400

    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)
