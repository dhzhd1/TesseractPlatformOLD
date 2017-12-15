# coding:utf-8

# Library Import
from flask import Flask, render_template, url_for, redirect
from flask_bootstrap3 import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField, SelectField
from wtforms.validators import Email, InputRequired, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


# app settings
app = Flask(__name__)
app.config['SECRET_KEY'] = 'TESSERACT_PALTFORM'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tesseract.db'
Bootstrap(app)

# Database Setup
db = SQLAlchemy(app)

# Authentication Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Define
class User(UserMixin, db.Model):
	__tablename__ = 'user'
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	username = db.Column(db.String(15), unique=True, nullable=False)
	email = db.Column(db.String(50), unique=True, nullable=False)
	password = db.Column(db.String(80), nullable=False)
	activate_status = db.Column(db.Boolean)
	group = db.Column(db.String(15), nullable=False)

	def __init__(self, username=None, password=None, email=None, activate_status=None, group=None):
		self.username = username
		self.password = password
		self.email = email
		self.group = group
		self.activate_status = activate_status

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


# Some constant
PREDEFINED_GROUPS=['admins', 'users']
COPYRIGHT_INFO_1 = u"Copyright© 2017 AMAX Information Technologies, Inc."
COPYRIGHT_INFO_2 = u"All Rights Reserved"

# Form Classes Define

class LoginForm(FlaskForm):
	username = StringField('User Name', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
	remember_me = BooleanField('Remember')

class NewUserForm(FlaskForm):
	username = StringField('User Name', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
	activate_status = BooleanField('Activated')
	email = StringField('Email', validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)])
	group = SelectField('Group', choices=PREDEFINED_GROUPS)


# Routing Define

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password == form.password.data):
				login_user(user, remember=form.remember_me)
				return redirect(url_for('dashboard'))
	return render_template('login.html',
	                       form=form,
	                       copyright_1=COPYRIGHT_INFO_1,
	                       copyright_2=COPYRIGHT_INFO_2,
	                       tiltle="Tesseract Platform for AI")

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
	# Todo: add a real dashboard page
	return "<h1>This is dashboard page</h1>"


@app.route('/users/add', methods=['GET', 'POST'])
def user_add():
	form = NewUserForm()
	if form.validate_on_submit():
		hashed_pass = generate_password_hash(form.password.data, method='sha256')
		new_user = User(username=form.username.data,
		                password=hashed_pass,
		                email=form.email.data,
		                group=form.group.data,
		                activate_status=form.activate_status.data)

		db.session.add(new_user)
		db.session.commit()
		return '<h1>New user has been created!</h1>'
	return render_template('add_user.html', form=form)

if __name__ == '__main__':
	app.run(debug=True)
