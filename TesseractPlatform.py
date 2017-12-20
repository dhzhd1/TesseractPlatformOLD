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
import subprocess,re


# app settings
app = Flask (__name__)
app.config['SECRET_KEY'] = 'TESSERACT_PALTFORM'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tesseract.db'
Bootstrap (app)

# Database Setup
db = SQLAlchemy (app)

# Authentication Setup
login_manager = LoginManager ()
login_manager.init_app (app)
login_manager.login_view = 'login'


# Database Define
class User (UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column (db.Integer, primary_key=True, autoincrement=True)
    username = db.Column (db.String (16), unique=True, nullable=False)
    email = db.Column (db.String (50), unique=True, nullable=False)
    password = db.Column (db.String (80), nullable=False)
    activate_status = db.Column (db.Boolean)
    group = db.Column (db.String (16), nullable=False)

    def __init__(self, username=None, password=None, email=None, activate_status=None, group=None):
        self.username = username
        self.password = password
        self.email = email
        self.group = group
        self.activate_status = activate_status


class Image (db.Model):
    __tablename__ = 'image'
    image_id = db.Column (db.String (12), primary_key=True)
    repository = db.Column (db.String (255), primary_key=True)
    image_tag = db.Column (db.String (255), primary_key=True)
    image_size = db.Column (db.String (16), nullable=False)
    image_owner = db.Column (db.String (16))
    image_type = db.Column (db.String (16))  # Public, Private, P-Share (Share with Group or User)
    image_rights = db.Column (db.String (1024))  # Format: u:100,u:101,g:1110,g:132   (u=User, g=Group)
    image_desc = db.Column (db.Text)

    def __init__(self, repository=None, image_tag=None, image_id=None, image_size=None, image_own=None, image_type=None,
                 image_rights=None, image_desc=None):
        self.repository = repository
        self.image_tag = image_tag
        self.image_id = image_id
        self.image_size = image_size
        self.image_owner = image_own
        self.image_type = image_type
        self.image_rights = image_rights
        self.image_desc = image_desc


class Instance (db.Model):
    __tablename__ = 'instance'
    id = db.Column (db.Integer, primary_key=True, autoincrement=True)  # treat as instance ID
    image_id = db.Column (db.String (12), nullable=False)
    instance_name = db.Column (db.String (64), nullable=False)
    instance_owner = db.Column (db.Integer, nullable=False)  # User.id
    with_gpu = db.Column (db.Boolean)
    gpu_ids = db.Column (db.Integer)
    share_folder = db.Column (db.String (1024))
    env_params = db.Column (db.String (2048))
    startup_params = db.Column (db.String (2048))

    # GPU IDs will be a b'1111111111111111' 16bit binary. Max is 65535.
    # each bit will stand for a gpu, and point to a GPU_ID which shows in nvidia-smi

    def __init__(self, image_id=None, instance_name=None, instance_owner=None, with_gpu=None,
                 gpu_ids=None, share_folder=None, env_params=None, startup_params=None):
        self.image_id = image_id
        self.instance_name = instance_name
        self.instance_owner = instance_owner
        self.with_gpu = with_gpu
        self.gpu_ids = gpu_ids
        self.share_folder = share_folder
        self.env_params = env_params
        self.startup_params = startup_params


class GpuDeviceInfo (db.Model):
    __tablename__ = 'gpu_info'
    uuid = db.Column (db.String (40), primary_key=True)
    prod_name = db.Column (db.String (64), nullable=False)
    prod_brand = db.Column (db.String (64), nullable=True)
    serial_num = db.Column (db.String (64), nullable=True)
    driver_ver = db.Column (db.String (16), nullable=False)
    bus_id = db.Column (db.String (32), nullable=False)
    gpu_id = db.Column (db.Integer, nullable=False)  # GPU id = [Attached GPUs] - [Minor Number] - 1
    gpu_image_version = db.Column (db.String (16), nullable=True)
    vbios_version = db.Column (db.String (16), nullable=True)
    total_mem = db.Column (db.Integer)
    ecc_mode = db.Column (db.String)
    share_mode = db.Column (db.String, nullable=True)

    def __init__(self, uuid=None, prod_name=None, prod_brand=None, serial_num=None, driver_ver=None,
                 bus_id=None, gpu_id=None, gpu_image_version=None, vbios_version=None, total_mem=None, ecc_mode=None,
                 share_mode="Exclusive"):
        self.uuid = uuid
        self.prod_brand = prod_brand
        self.prod_name = prod_name
        self.serial_num = serial_num
        self.driver_ver = driver_ver
        self.bus_id = bus_id
        self.gpu_id = gpu_id
        self.gpu_image_version = gpu_image_version
        self.vbios_version = vbios_version
        self.total_mem = total_mem
        self.ecc_mode = ecc_mode
        self.share_mode = share_mode


@login_manager.user_loader
def load_user(user_id):
    return User.query.get (int (user_id))


# Some constant
PREDEFINED_GROUPS = ['admins', 'users']
COPYRIGHT_INFO_1 = u"Copyright© 2017 AMAX Information Technologies, Inc."
COPYRIGHT_INFO_2 = u"All Rights Reserved"


# Form Classes Define

class LoginForm (FlaskForm):
    username = StringField ('User Name', validators=[InputRequired (), Length (min=4, max=15)])
    password = PasswordField ('Password', validators=[InputRequired (), Length (min=8, max=80)])
    remember_me = BooleanField ('Remember')


class NewUserForm (FlaskForm):
    username = StringField ('User Name', validators=[InputRequired (), Length (min=4, max=15)])
    password = PasswordField ('Password', validators=[InputRequired (), Length (min=8, max=80)])
    activate_status = BooleanField ('Activated')
    email = StringField ('Email', validators=[InputRequired (), Email (message="Invalid email"), Length (max=50)])
    group = SelectField ('Group', choices=PREDEFINED_GROUPS)


class NewInstanceForm (FlaskForm):
    ## TODO: Change the selection choices into a dynamic values which comes from database
    ## Ref: http://wtforms.simplecodes.com/docs/0.6.1/fields.html
    image_repository = SelectField ('Repository', validators=[InputRequired ()],
                                    choices=[('all', 'All'), ('amax/ai', 'amax/ai'), ('amax/general', 'amax/general')],
                                    default=all)
    # image_tag = SelectField('Image Tag', validators=[InputRequired()],
    # 						choices=[(None, ''), ('tensorflow', 'tensorflow'), ('mxnet', 'mxnet')], default=None)

    image_tag = SelectField ('Image Tag', validators=[InputRequired ()],
                             choices=[('None', '')] + [(e.image_id, e.image_tag) for e in Image.query.all ()], default=None)
    instance_name = StringField ('Instance Name', validators=[InputRequired (), Length (min=4, max=64)])
    instance_owner = StringField ('Owner')
    need_gpu = BooleanField ('Need GPU Resource', default=True)
    select_gpu = SelectMultipleField ('Select GPU',
                                      choices=[('all', 'All GPUs'), ('0', 'GPU-0'), ('1', 'GPU-1'), ('2', 'GPU-2'),
                                               ('3', 'GPU-3'),
                                               ('4', 'GPU-4'), ('5', 'GPU-5'), ('6', 'GPU-6'), ('7', 'GPU-7')],
                                      default='all')
    image_id = StringField ('Image ID', validators=[InputRequired ()])
    share_folder_src = StringField ('Folder Mapping From')
    share_folder_dest = StringField ('Folder Mapping To')
    param_list = StringField ('Environment Parameters')
    other_startup_params = StringField ('Container Startup Parameters')


# Routing Define

@app.route ('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm ()
    if form.validate_on_submit ():
        user = User.query.filter_by (username=form.username.data).first ()
        if user:
            if check_password_hash (user.password, form.password.data):
                login_user (user, remember=form.remember_me)
                return redirect (url_for ('dashboard'))
    return render_template ('login.html',
                            form=form,
                            copyright_1=COPYRIGHT_INFO_1,
                            copyright_2=COPYRIGHT_INFO_2,
                            title="Tesseract Platform for AI")


@app.route ('/logout')
@login_required
def logout():
    logout_user ()
    return redirect (url_for ('login'))


@app.route ('/')
@app.route ('/dashboard')
@login_required
def dashboard():
    return render_template ('dashboard.html', title="Dashboard - Tesseract Platform")


@app.route ('/images', methods=['GET', 'POST'])
@login_required
def images():
    images = Image.query.all ()
    return render_template ('images.html', title="Images - Tesseract Platform",
                            images=images,
                            update_timestamp=str (datetime.now ()))


@app.route ('/new-instance', methods=['GET', 'POST'])
@login_required
def new_instance():
    form = NewInstanceForm ()
    if form.validate_on_submit ():
        inst = Instance ()
        inst.image_id = form.image_id.data
        inst.instance_name = form.instance_name.data
        inst.instance_owner = form.instance_owner.data
        inst.with_gpu = form.need_gpu.data
        inst.gpu_ids = form.select_gpu.data
        try:
            db.session.add (inst)
            db.session.commit ()
            result = "succeed"
        except:
            result = "failed"
        finally:
            return render_template ('new_instance.html', form=form, title="New Instance - Tesseract Platform",
                                    result=result)
    return render_template ('new_instance.html', form=form, title="New Instance - Tesseract Platform", result="")


@app.route ('/hw-info', methods=['GET', 'POST'])
def hw_info():
    # TODO: at this moment, only GPU information was provided. System information will be provided later.
    gpus = GpuDeviceInfo.query.all ()
    return render_template ('hardware_info.html', title="Hardware Information - Tesseract Platform", gpus=gpus)


@app.route ('/users/add', methods=['GET', 'POST'])
@login_required
def user_add():
    form = NewUserForm ()
    if form.validate_on_submit ():
        hashed_pass = generate_password_hash (form.password.data, method='sha256')
        new_user = User (username=form.username.data,
                         password=hashed_pass,
                         email=form.email.data,
                         group=form.group.data,
                         activate_status=form.activate_status.data)
        try:
            db.session.add (new_user)
            db.session.commit ()
            result = "succeed"
        except:
            result = "failed"
        finally:
            return render_template ('add_user.html', form=form, result=result)
    return render_template ('add_user.html', form=form, result="")

@app.route('/images/update-db')
@login_required
def update_db():
    raw_output = subprocess.check_output (['docker', 'images', '--no-trunc']).split('\n')
    raw_output = [x for x in raw_output[1:] if x != '']
    pattern = r"\S+"
    for line in raw_output:
        columns = re.findall (pattern, line)
        # Columns[0] is 'Repository'
        # Columns[1] is 'Tag'
        # Columns[2] is 'Image ID' without truncated
        # Columns[-1] is 'Size of the Image'
        image_record = Image (repository=columns[0], image_tag=columns[1], image_id=columns[2], image_size=columns[-1],
                              image_type='Public')
        try:
            db.session.add (image_record)
            db.session.commit ()
        except Exception as e:
            db.session.rollback ()

    ## TODO: Only add the new added image. the delete image will not be remove from database
    return redirect(url_for('images'))

if __name__ == '__main__':
    app.run (debug=True)
