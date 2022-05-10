from enum import unique
from django.forms import FileField, IntegerField
from flask import Flask, redirect, url_for, request, render_template,flash, session 
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, IntegerField,RadioField
from wtforms.validators import DataRequired, EqualTo, Length, Email
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf.file import FileField
from werkzeug.utils import secure_filename
import uuid as uuid

# Create a Flask Instance
app = Flask(__name__)
# Add Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password123@localhost/carhub_users'

#Secret Key
app.config['SECRET_KEY'] = "its the secret key"

staticpath = "/root/carhub/static/"

# Initialize the Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Flask_Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# Adding User database table (Creating Model)
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False,unique=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    user_type = db.Column(db.String(100), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    #Doing some password stuff
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute!")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


class Products(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(120), nullable=False)
    seller_name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    car_type = db.Column(db.String(120), nullable=False)
    product_img1 = db.Column(db.String(120), nullable=False)
    product_img2 = db.Column(db.String(120), nullable=False)
    product_img3 = db.Column(db.String(120), nullable=False)
    product_img4 = db.Column(db.String(120), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)



#Creating a form class for user registration
class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    user_type = RadioField("UserType",choices=[('user','Customer'),('seller','Seller')], default='user')
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField("Submit")

class ProofUser(FlaskForm):
    user_img1 = FileField("Aadhar",validators=[DataRequired()])
    user_img2 = FileField("Licence",validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")


class ProductForm(FlaskForm):
    product_name = StringField("Product Name", validators=[DataRequired()])
    seller_name = StringField("Seller Name", validators=[DataRequired()])
    price = IntegerField("Price", validators=[DataRequired()])
    car_type = RadioField("CarType",choices=[('petrol','Petrol Engine'),('electric','Electric Engine')], default='petrol')
    product_img1 = FileField("Car Image Upload",validators=[DataRequired()])
    product_img2 = FileField("Aadhar",validators=[DataRequired()])
    product_img3 = FileField("Licence",validators=[DataRequired()])
    product_img4 = FileField("Other Proof",validators=[DataRequired()])
    submit = SubmitField("Add Product")


class ProductSubmitForm(FlaskForm):
    add_product = StringField("Username", validators=[DataRequired()]) 
    submit = SubmitField("Continue To Checkout")


@app.route('/')
def home():
    cars = Products.query.order_by(Products.date_added).filter(Products.car_type=="petrol")
    return render_template("home.html",cars=cars)
    



#Login Route
@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # check hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login Successfull...")
                if current_user.user_type == "admin":
                    return redirect(url_for('admin_dashboard'))
                elif current_user.user_type == "seller":
                    return redirect(url_for('seller_dashboard'))
                elif current_user.user_type == "user":
                    return redirect(url_for('user_dashboard'))
            
            else:
                flash("Wrong Username or Password")
        else:
            flash("Wrong Username or Password")
    return render_template("login.html",form=form)


# Create Logout Page
@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash("You Have Been Loged Out!")
    return redirect(url_for('login'))




#Adding user route
@app.route('/user/add', methods=['GET','POST'])
def add_user():
    form = UserForm() 
    # Hash the Password!
    hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
    email = None
    name = None
    
    if form.validate_on_submit(): 
        user = Users.query.filter_by(email=form.email.data).first()  #to check if email exists. if returns None there is no user so we can let them add new user.
        if user is None:
            user = Users(name=form.name.data, email=form.email.data, password_hash=hashed_pw, username=form.username.data,user_type=form.user_type.data)
            db.session.add(user)
            db.session.commit()
            flash("User added succesfully")
        else:
            flash("Unable To Add New User Pls Try Again After Some Time...")
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.password_hash.data = ''
                
    return render_template("register.html",form=form,name=name)


# delete route
@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm() 
    our_users = Users.query.order_by(Users.date_added)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted successfully")
        return render_template("/admin/admin_dashboard.html",form=form,name=name,our_users=our_users)
    except:
        flash("whoops! There is a problem deleting user")
        return render_template("/admin/admin_dashboard.html",form=form,name=name,our_users=our_users)



@app.route('/admin/dashboard', methods=['GET','POST'])
@login_required
def admin_dashboard():
    if current_user.user_type == "admin":
        our_users = Users.query.order_by(Users.date_added)
        products = Products.query.order_by(Products.date_added)
        return render_template("/admin/admin_dashboard.html",our_users=our_users,products=products)
    return "<h1>You Have To be admin to access this page</h1>"


@app.route('/user/dashboard/', methods=['GET','POST'])
@login_required
def user_dashboard():
    if current_user.user_type == "user":
        cars = Products.query.order_by(Products.date_added)
        return render_template("/user/user_dashboard.html",cars=cars)
    return "<h1>Unauthorized</h1>"


@app.route('/user/dashboard/rent/<int:id>/', methods=['GET','POST'])
@login_required
def user_rent(id):
    if current_user.user_type == "user":
        car = Products.query.get_or_404(id)
        form=ProductSubmitForm()
        form2=ProofUser()
        return render_template("/user/booknow.html",car=car,form=form,form2=form2)
    return "<h1>Unauthorized</h1>"


@app.route('/seller/dashboard',methods=['GET','POST'])
@login_required
def seller_dashboard():
    if current_user.user_type == "seller":
        form = ProductForm()
        product_name = None
        seller_name = None
        price = None

        if form.validate_on_submit(): 
            
            product_img1=form.product_img1.data
            product_img2=form.product_img2.data
            product_img3=form.product_img3.data
            product_img4=form.product_img4.data
            #GRAB Image Name
            car_img1_filename = secure_filename(product_img1.filename) 
            car_img2_filename = secure_filename(product_img2.filename)
            car_img3_filename = secure_filename(product_img3.filename)
            car_img4_filename = secure_filename(product_img4.filename)
            #Set UUID
            car_img1_name = str(uuid.uuid1()) + '_' + car_img1_filename
            car_img2_name = str(uuid.uuid1()) + '_' + car_img2_filename
            car_img3_name = str(uuid.uuid1()) + '_' + car_img3_filename
            car_img4_name = str(uuid.uuid1()) + '_' + car_img4_filename

            # Save Car images to local storage
            try:
                product_img1.save(staticpath+car_img1_name)
                product_img2.save(staticpath+car_img2_name)
                product_img3.save(staticpath+car_img3_name)
                product_img4.save(staticpath+car_img4_name)
            except:
                pass

            add_product = Products(product_name=form.product_name.data, seller_name=form.seller_name.data, price=form.price.data,product_img1=car_img1_name,product_img2=car_img2_name,product_img3=car_img3_name,product_img4=car_img4_name,car_type=form.car_type.data)
            db.session.add(add_product)
            db.session.commit()
            flash("New car added succesfully")
            form.product_name.data = ''
            form.seller_name.data = ''
            form.price.data = ''
        products = Products.query.order_by(Products.date_added)   
        return render_template("/seller/seller_dashboard.html", form=form,products=products)
    return "<h1>Unauthorized</h1>"


@app.route('/rent_cars/delete/<int:id>')
def delete_product(id):
    product_to_delete = Products.query.get_or_404(id)
    product_name = None
    form = ProductForm() 
    products = Products.query.order_by(Products.date_added)
    try:
        db.session.delete(product_to_delete)
        db.session.commit()
        flash("Product deleted successfully")
        return render_template("/admin/admin_dashboard.html", form=form,products=products)
    except:
        flash("whoops! There is a problem deleting user")
        return render_template("/admin/admin_dashboard.html", form=form,products=products)

#rent car view petrol 
@app.route('/rent_cars/1/')
def cars_view1():
    cars = Products.query.order_by(Products.date_added).filter(Products.car_type=="petrol")
    return render_template("petrol_cars.html",cars=cars)

#rent car view electric
@app.route('/rent_cars/2/')
def cars_view2():
    cars = Products.query.order_by(Products.date_added).filter(Products.car_type=="electric")
    return render_template("electric_cars.html",cars=cars)



#FLASK_APP=new.py flask run
# export FLASK_ENV=development  To debug