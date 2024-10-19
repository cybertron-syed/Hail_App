from flask import Flask, render_template, redirect, url_for, request, session, flash
import boto3
from botocore.exceptions import ClientError
import msal
import os
from itsdangerous import URLSafeTimedSerializer
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, Regexp
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
AWS_REGION = os.getenv('AWS_REGION')

cognito = boto3.client('cognito-idp', region_name=AWS_REGION)
ses = boto3.client('ses', region_name=AWS_REGION)

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    first_name = StringField('First Name (Optional)')
    last_name = StringField('Last Name (Optional)')
    password = PasswordField('Password', validators=[
        InputRequired(),
        Length(min=8, message='Password must be at least 8 characters long.'),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)', message='Password must contain at least one letter and one number.')
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class VerificationForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    code = StringField('Verification Code', validators=[InputRequired()])
    submit = SubmitField('Verify')

class ResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Submit')

class ConfirmResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    code = StringField('Reset Code', validators=[InputRequired()])
    new_password = PasswordField('New Password', validators=[
        InputRequired(),
        Length(min=8, message='Password must be at least 8 characters long.'),
        Regexp(r'^(?=.*[A-Za-z])(?=.*\d)', message='Password must contain at least one letter and one number.')
    ])
    submit = SubmitField('Reset Password')

@app.route('/')
def home():
    form = LoginForm() 
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            response = cognito.sign_up(
                ClientId=COGNITO_CLIENT_ID,
                Username=form.email.data,
                Password=form.password.data,
                UserAttributes=[
                    {'Name': 'email', 'Value': form.email.data},
                    {'Name': 'given_name', 'Value': form.first_name.data or ''},
                    {'Name': 'family_name', 'Value': form.last_name.data or ''}
                ]
            )
            send_welcome_email(form.email.data)
            flash('Registration successful! Please check your email for the verification code.', 'success')
            return redirect(url_for('verify'))
        except ClientError as e:
            flash(e.response['Error']['Message'], 'danger')
    return render_template('register.html', form=form)

def send_welcome_email(email):
    subject = "Hi, welcome to HAIL"
    body_text = "Welcome to HAIL! Please verify your email."
    try:
        response = ses.send_email(
            Source='mailtoshaarikh@gmail.com',
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': body_text}}
            }
        )
    except ClientError as e:
        error_message = e.response['Error']['Message']
        flash(f"Failed to send email: {error_message}", 'danger')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    form = VerificationForm()
    if form.validate_on_submit():
        try:
            response = cognito.confirm_sign_up(
                ClientId=COGNITO_CLIENT_ID,
                Username=form.email.data,
                ConfirmationCode=form.code.data
            )
            flash('Email verified successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except ClientError as e:
            flash(e.response['Error']['Message'], 'danger')
    return render_template('verify.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def forgot_password():
    form = ResetForm() 
    if form.validate_on_submit():
        try:
            response = cognito.forgot_password(
                ClientId=COGNITO_CLIENT_ID,
                Username=form.email.data,
            )
            send_reset_email(form.email.data)
            flash('A reset code has been sent to your email.', 'success')
            return redirect(url_for('confirm_reset_password', email=form.email.data))
        except ClientError as e:
            flash(e.response['Error']['Message'], 'danger')
    return render_template('reset.html', form=form)

@app.route('/confirm_reset_password', methods=['GET', 'POST'])
def confirm_reset_password():
    form = ConfirmResetPasswordForm()  
    if form.validate_on_submit():
        try:
            response = cognito.confirm_forgot_password(
                ClientId=COGNITO_CLIENT_ID,
                Username=form.email.data,
                ConfirmationCode=form.code.data,  
                Password=form.new_password.data  
            )
            flash('Your password has been reset successfully.', 'success')
            return redirect(url_for('login'))
        except ClientError as e:
            flash(e.response['Error']['Message'], 'danger')
    return render_template('confirm_reset_password.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            response = cognito.initiate_auth(
                ClientId=COGNITO_CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': form.email.data,
                    'PASSWORD': form.password.data
                }
            )
            session['user'] = form.email.data
            flash('Logged in successfully!', 'success')
            return redirect(url_for('welcome'))
        except ClientError as e:
            flash(e.response['Error']['Message'], 'danger')
    return render_template('login.html', form=form)

@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    if 'user' in session:
        return render_template('welcome.html', user=session['user'])
    else:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
