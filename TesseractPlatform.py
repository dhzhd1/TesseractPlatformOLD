# coding:utf-8

# Library Import
from flask import Flask, render_template, url_for, redirect
from flask_bootstrap3 import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField, SelectField, SelectMultipleField
from wtforms.validators import Email, InputRequired, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime


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


class Image(db.Model):
	__tablename__ = 'image'
	image_id = db.Column(db.String(12), primary_key=True)
	repository = db.Column(db.String(255), nullable=False)
	image_tag = db.Column(db.String(255), nullable=False)
	image_size = db.Column(db.String(16), nullable=False)

	def __init__(self, repository=None, image_tag=None, image_id=None, image_size=None):
		self.repository = repository
		self.image_tag = image_tag
		self.image_id = image_id
		self.image_size = image_size

class Instance(db.Model):
	__tablename__ = 'instance'
	id = db.Column(db.Integer, primary_key=True, autoincrement=True) #treat as instance ID
	image_id = db.Column(db.String(12), nullable=False)
	instance_name = db.Column(db.String(64), nullable=False)
	instance_owner = db.Column(db.Integer, nullable=False)  # User.id
	with_gpu = db.Column(db.Boolean)
	gpu_ids = db.Column(db.Integer)
	# GPU IDs will be a b'1111111111111111' 16bit binary. Max is 65535.
	# each bit will stand for a gpu, and point to a GPU_ID which shows in nvidia-smi




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

class NewInstanceForm(FlaskForm):
	## TODO: Change the selection choices into a dynamic values which comes from database
	## Ref: http://wtforms.simplecodes.com/docs/0.6.1/fields.html
	image_repository = SelectField('Repository', validators=[InputRequired()], choices=[('all', 'All'),('amax/ai','amax/ai'),('amax/general','amax/general')], default=all)
	image_tag = SelectField('Image Tag', validators=[InputRequired()], choices=[(None, ''),('tensorflow', 'tensorflow'),('mxnet', 'mxnet')], default=None)
	instance_name = StringField('Instance Name', validators=[InputRequired(),Length(min=4, max=64)])
	instance_owner = StringField('Owner')
	need_gpu = BooleanField('Need GPU Resource', default=True)
	select_gpu = SelectMultipleField('Select GPU', choices=[('0','GPU-0'),('1','GPU-1')])
	image_id = StringField('Image ID', validators=[InputRequired()])



# Routing Define

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password, form.password.data):
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
	return render_template('dashboard.html', title="Dashboard - Tesseract Platform")



@app.route('/images', methods=['GET', 'POST'])
@login_required
def images():
	dummy_images = []
	dummy_images.append(Image(image_id='28093d93b19e',
	                          image_tag='tensorflow_cuda8.0-cudnn7.0-devel_ubuntu16.04_v01',
	                          repository='amax/ai',
	                          image_size='5.3GB'))
	dummy_images.append(Image(image_id='fa846598234f',
	                          image_tag='mxnet_cuda9.0-cudnn7.0-devel_ubuntu16.04_v01',
	                          repository='amax/ai',
	                          image_size='6.31GB'))
	dummy_images.append(Image(image_id='4269e59080c0',
	                          image_tag='8.0-devel-cudnn7.0_ubuntu16.04_v01',
	                          repository='amax/general',
	                          image_size='2.11GB'))
	dummy_images.append(Image(image_id='9ab2e04de99f',
	                          image_tag='9.0-devel-cudnn7.0_ubuntu17.04_v01',
	                          repository='amax/general',
	                          image_size='1.71GB'))

	return render_template('images.html', title="Images - Tesseract Platform",
	                       images=dummy_images,
	                       update_timestamp=str(datetime.now()))


@app.route('/new-instance', methods=['GET', 'POST'])
@login_required
def new_instance():
	form = NewInstanceForm()
	if form.validate_on_submit():
		inst = Instance()
		inst.image_id = form.image_id.data
		inst.instance_name = form.instance_name.data
		inst.instance_owner = form.instance_owner.data
		inst.with_gpu = form.need_gpu.data
		inst.gpu_ids = form.select_gpu.data
		try:
			db.session.add(inst)
			db.session.commit()
			result = "succeed"
		except:
			result = "failed"
		finally:
			return render_template('new_instance.html', form=form, title="New Instance - Tesseract Platform",result=result)
	return render_template('new_instance.html', form=form, title="New Instance - Tesseract Platform", result="")


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
		try:
			db.session.add(new_user)
			db.session.commit()
			result = "succeed"
		except :
			result = "failed"
		finally:
			return render_template('add_user.html', form=form, result=result)
	return render_template('add_user.html', form=form, result="")

if __name__ == '__main__':
	app.run(debug=True)
