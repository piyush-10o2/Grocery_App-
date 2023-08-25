from flask import Flask, render_template, redirect, flash, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, IntegerField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from pyecharts import options as opts
from pyecharts.charts import Bar

# Flask App Configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'mad1p_key'

# Initialize SQLAlchemy with the app
db = SQLAlchemy(app)

# Initializing bcrypt and linking it to our app for hashing 
bcrypt = Bcrypt(app)

# This is for manager side:
# Initializing LoginManager, basically helps our app in implementing proper login behaviour 
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# The user_loader callback helps in loading the user object from the user_id stored in the session
@login_manager.user_loader
def load_user(user_id):
  return Manager.query.get(int(user_id))

# Now we create our Managers table
class Manager(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key = True)
  username = db.Column(db.String(50), nullable = False, unique = True)
  password = db.Column(db.String(80), nullable = False)

# Now we create our Users table
class User(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key = True)
  username = db.Column(db.String(50), nullable = False, unique = True)
  password = db.Column(db.String(80), nullable = False)
  
# Category table
class Category(db.Model):
  cat_id = db.Column(db.Integer, primary_key=True)
  cat_name = db.Column(db.String(100), nullable=False)
  # lazy = 'select' (set as default when lazy = True)
  # lazy = 'join' 
  # lazy = 'dynamic'
  products = db.relationship('Product', backref='category', lazy=True)
  # this lazy=True parameter in the db.relationship declaration means that the related Category objects will be lazily loaded using the default   "select" strategy. This is a reasonable choice in many cases, as it means the related category will be fetched from the database only when      you access the category attribute of a Product object.

# Product table
class Product(db.Model):
  prod_id = db.Column(db.Integer, primary_key=True)
  prod_name = db.Column(db.String(100), nullable=False)
  price = db.Column(db.Float, nullable=False) # price per unit (subjective)
  quantity = db.Column(db.Integer, nullable=False) # stock amount remaining (not visible to user)
  # Foreign key relationship with the Category table
  cat_id = db.Column(db.Integer, db.ForeignKey('category.cat_id'), nullable=False)
  # category = db.relationship('Category', backref=db.backref('Product', lazy=True))

# Cart table
class Cart(db.Model):
  cart_id = db.Column(db.Integer, primary_key=True)
  product_id = db.Column(db.Integer, nullable=False)
  product_name = db.Column(db.String(100), nullable=False)
  quantity = db.Column(db.Integer, default=0)
  price = db.Column(db.Float, default=0.0)  

  # This representation function is for debugging purposes only
  def __repr__(self):
    return f"<Cart(product_id={self.product_id}, product_name='{self.product_name}', quantity={self.quantity}, price={self.price})>"

# Clearing the database file for demonstration purpose
def reset_database():
    with app.app_context():
        # Drop and create only the Category table
        db.drop_all()
        db.create_all()

reset_database()

# in this case, the data from previous executions is saved as well
# with app.app_context():
#   db.create_all()

# mr_username indicates that the variable is for a new manager
class Manager_RegistrationForm(FlaskForm):
  mr_username = StringField(validators = [InputRequired(), Length(min = 4, max = 50)], render_kw = {"placeholder": "Username"})
  mr_password = PasswordField(validators = [InputRequired(), Length(min = 4, max = 20)], render_kw = {"placeholder": "Password"})
  mr_submit = SubmitField("Register Manager")

  # Check if the username is unique or not
  def validate_username(self, username):
    existing_manager_username = Manager.query.filter_by(username = username.data).first()
    if existing_manager_username:
      raise ValidationError(
        "This username has already been taken. Please try a different one."
      )
      
# m_username indicates that the variable is for a registered manager
class Manager_LoginForm(FlaskForm):
  m_username = StringField(validators = [InputRequired(), Length(min = 4, max = 50)], render_kw = {"placeholder": "Username"})
  m_password = PasswordField(validators = [InputRequired(), Length(min = 4, max = 20)], render_kw = {"placeholder": "Password"})
  m_submit = SubmitField("Login as Manager")

# ur_username indicates that the variable is for a new user
class User_RegistrationForm(FlaskForm):
  ur_username = StringField(validators = [InputRequired(), Length(min = 4, max = 50)], render_kw = {"placeholder": "Username"})
  ur_password = PasswordField(validators = [InputRequired(), Length(min = 4, max = 20)], render_kw = {"placeholder": "Password"})
  ur_submit = SubmitField("Register User")

  # Check if the username is unique or not
  def validate_username(self, username):
    existing_user_username = User.query.filter_by(username = username.data).first()
    if existing_user_username:
      raise ValidationError(
        "This username has already been taken. Please try a different one."
      )
      
# m_username indicates that the variable is for a registered manager
class User_LoginForm(FlaskForm):
  u_username = StringField(validators = [InputRequired(), Length(min = 4, max = 50)], render_kw = {"placeholder": "Username"})
  u_password = PasswordField(validators = [InputRequired(), Length(min = 4, max = 20)], render_kw = {"placeholder": "Password"})
  u_submit = SubmitField("Login as User")
  
class Create_cat(FlaskForm):
  cat_name = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Category Name"})
  create_category = SubmitField("Create Category")

class AddProductForm(FlaskForm):
    prod_name = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Product Name"})
    price_per_unit = FloatField(validators=[InputRequired()], render_kw={"placeholder": "Price per Unit"})
    quantity_in_stock = IntegerField(validators=[InputRequired()], render_kw={"placeholder": "Quantity Remaining"})
    add_product = SubmitField("Add Product")

# Routes
# The @app.route("/") decorator is used to specify that a particular function should be called when the application receives a request for the root URL ("/").
@app.route("/")
def welcome_Page():
  return render_template("home.html")

@app.route("/static/")
def statics():
  return render_template("README.txt")

# Manager Registration
@app.route("/register_manager", methods = ["GET", "POST"])
def manager_register():
  form = Manager_RegistrationForm()

  if form.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(form.mr_password.data)
    new_manager = Manager(username = form.mr_username.data, password = hashed_password)
    db.session.add(new_manager)
    db.session.commit()
    return redirect(url_for('manager_login'))
  return render_template("manager_registration.html", form = form)

# Manager Login
@app.route("/login/manager", methods = ["GET", "POST"])
def manager_login():
  form = Manager_LoginForm()
  if form.validate_on_submit():
    manager = Manager.query.filter_by(username = form.m_username.data).first()
    if manager:
      if bcrypt.check_password_hash(manager.password, form.m_password.data):
        login_user(manager)
        return redirect(url_for('manager_dash'))
    else:
      flash("This manager does not exist. Please register before login.", "error")
  return render_template("manager_login.html", form = form)

# Manager Dashboard
@app.route("/manager_dash", methods = ["GET", "POST"])
@login_required
def manager_dash():
  return render_template("manager_dashboard.html")

# User Registration
@app.route("/register_user", methods = ["GET", "POST"])
def user_register():
  form = User_RegistrationForm()

  if form.validate_on_submit():
    hashed_password = bcrypt.generate_password_hash(form.ur_password.data)
    new_user = User(username = form.ur_username.data, password = hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('user_login'))
  return render_template("user_registration.html", form = form)

# User Login  
@app.route("/login/user", methods = ["GET", "POST"])
def user_login():
  form = User_LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(username = form.u_username.data).first()
    if user:
      if bcrypt.check_password_hash(user.password, form.u_password.data):
        login_user(user)
        return redirect(url_for('user_dash'))
    else:
      flash("This user does not exist. Please register before login.", "error")
  
  return render_template("user_login.html", form = form)

# User Dashboard
@app.route("/user_dash", methods=["GET", "POST"])
@login_required
def user_dash():
    categories = Category.query.all()
    return render_template("user_dashboard.html", categories=categories)
  
# Route for creating a category
@app.route("/create_category", methods=["GET", "POST"])
def create_category():
    form = Create_cat()
    if form.validate_on_submit():  # Check if the form is submitted and valid
        new_category = Category(cat_name=form.cat_name.data)
        db.session.add(new_category)
        db.session.commit()
        return redirect(url_for('manager_dash'))

    return render_template("create_cat.html", form=form)

# Route for editing a category
@app.route("/edit_category/<int:category_id>", methods=["GET", "POST"])
def edit_category(category_id):
    category = Category.query.get(category_id)
    if category is None:
        return "Category not found", 404

    if request.method == "POST":
        new_category_name = request.form.get("new_category_name")
        category.cat_name = new_category_name
        db.session.commit()
        return redirect(url_for("show_categories"))

    return render_template("edit_cat.html")

# Route for Deleting a category
@app.route("/delete_category/<int:category_id>", methods=["POST"])
def delete_category(category_id):
    category = Category.query.get(category_id)
    if category:
        # Delete associated products
        products = Product.query.filter_by(cat_id=category_id).all()
        for product in products:
            db.session.delete(product)
        db.session.commit()

        # Delete the category
        db.session.delete(category)
        db.session.commit()

    return redirect(url_for("show_categories"))
  
# Route to display the categories
@app.route("/show_categories")
def show_categories():
    categories = Category.query.all()
    return render_template("categories.html", categories=categories)

# Route to display all products
@app.route("/view_products")
def view_products():
    products = Product.query.all()
    return render_template("products.html", products=products)

# Route to delete a particular product
@app.route("/delete_product/<int:product_id>", methods=["POST"])
def delete_product(product_id):
    product = Product.query.get(product_id)
    if product:
        db.session.delete(product)
        db.session.commit()
    return redirect(url_for("view_products"))
  
# Route to add product(s) to a category
@app.route("/add_product/<int:category_id>", methods=["GET", "POST"])
def add_product(category_id):
    category = Category.query.get(category_id)
    if category is None:
        return "Category not found", 404

    form = AddProductForm()
    if form.validate_on_submit():
        # Create and add the product to the category
        new_product = Product(
          prod_name=form.prod_name.data,
          price=form.price_per_unit.data,
          quantity=form.quantity_in_stock.data,
          cat_id=category_id  # Use the category_id from the URL
        )
        db.session.add(new_product)
        db.session.commit()
        return redirect(url_for("show_categories"))

    return render_template("addprod_cat.html", form=form, category=category)

# Route for editing a product
@app.route("/edit_product/<int:product_id>", methods=["GET", "POST"])
def edit_product(product_id):
    product = Product.query.get(product_id)
    if product is None:
        return "Product not found", 404

    if request.method == "POST":
        new_product_name = request.form.get("new_prod_name")
        product.prod_name = new_product_name
        new_price_per_unit = request.form.get("new_price_per_unit")
        product.price = new_price_per_unit
        new_quant = request.form.get("new_quantity")
        product.quantity = new_quant
        db.session.commit()
        return redirect(url_for("view_products"))

    return render_template("edit_prod.html")
  
# Route for add to cart functionality
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_id = int(request.form.get('product_id'))
    product_name = request.form.get('product_name')
    product_price = float(request.form.get('product_price'))
    quantity = int(request.form.get('quantity'))

    # Fetch the selected product from the database
    selected_product = Product.query.get(product_id)

    if selected_product is None:
        flash("Product not found.", "danger")
        return redirect(url_for('user_dash'))

    if quantity <= 0:
        flash("Quantity must be greater than 0 to add the item to the cart.", "warning")
        return redirect(url_for('user_dash'))

    if quantity > selected_product.quantity:
        flash("Requested quantity exceeds available stock.", "warning")
        return redirect(url_for('user_dash'))

    # Check if the product is already in the cart
    cart_item = Cart.query.filter_by(product_id=product_id).first()

    if cart_item:
        # If the product is already in the cart, update its quantity
        cart_item.quantity += quantity
    else:
        # If the product is not in the cart, add it as a new item
        cart_item = Cart(product_id=product_id, product_name=product_name, price=product_price, quantity=quantity)
        db.session.add(cart_item)

    # Update the available quantity in the Product table
    selected_product.quantity -= quantity

    db.session.commit()
    return redirect(url_for('user_dash'))

# Route for view cart
@app.route('/view_cart')
def view_cart():
    # Fetch items from the cart
    cart_items = Cart.query.all()

    # Calculate the total bill amount
    total_amount = sum(item.price * item.quantity for item in cart_items)

    return render_template('view_cart.html', cart_items=cart_items, total_amount=total_amount)

# Route to reset the cart
# @app.route("/reset_cart", methods=["POST"])
# def reset_cart():
#     # Delete all items from the cart
#     Cart.query.delete()
#     db.session.commit()
#     flash("Cart has been reset.", "success")
#     return redirect(url_for('user_dash'))

# Route for summary 
@app.route("/summary")
def summary():
    categories = [category.cat_name for category in Category.query.all()]
    product_counts = [len(category.products) for category in Category.query.all()]

    bar_product_count = (
        Bar(init_opts=opts.InitOpts(bg_color="#1a1a1a"))  # Set background color
        .add_xaxis(categories)
        .add_yaxis("Number of Products", product_counts)
        .set_series_opts(label_opts=opts.LabelOpts(color="#c8fc90"))  # Set label color
        .set_global_opts(
            title_opts=opts.TitleOpts(
                title="Summary",
                title_textstyle_opts=opts.TextStyleOpts(color="#c8fc90"),  # Set title color
                subtitle="Products Per Category",
                subtitle_textstyle_opts=opts.TextStyleOpts(color="#c8fc90"),  # Set subtitle color
            ),
            legend_opts=opts.LegendOpts(textstyle_opts=opts.TextStyleOpts(color="#c8fc90")),  # Set legend color
            xaxis_opts=opts.AxisOpts(axislabel_opts=opts.LabelOpts(color="#c8fc90")),  # Set X-axis label color
            yaxis_opts=opts.AxisOpts(axislabel_opts=opts.LabelOpts(color="#c8fc90")),  # Set Y-axis label color
        )
    )

    bar_product_price = (
        Bar(init_opts=opts.InitOpts(bg_color="#1a1a1a"))  # Set background color
        .add_xaxis(
            [max(category.products, key=lambda product: product.price).prod_name for category in Category.query.all()]
        )
        .add_yaxis(
            "Costliest Product Price",
            [max(category.products, key=lambda product: product.price).price for category in Category.query.all()],
        )
        .set_series_opts(label_opts=opts.LabelOpts(color="#c8fc90"))  # Set label color
        .set_global_opts(
            title_opts=opts.TitleOpts(
                title=" ",
                subtitle="Costliest Product Price Per Category",
                subtitle_textstyle_opts=opts.TextStyleOpts(color="#c8fc90"),  # Set subtitle color
            ),
            legend_opts=opts.LegendOpts(textstyle_opts=opts.TextStyleOpts(color="#c8fc90")),  # Set legend color
            xaxis_opts=opts.AxisOpts(axislabel_opts=opts.LabelOpts(color="#c8fc90")),  # Set X-axis label color
            yaxis_opts=opts.AxisOpts(axislabel_opts=opts.LabelOpts(color="#c8fc90")),  # Set Y-axis label color
        )
    )

    chart_product_count = bar_product_count.render_embed()
    chart_product_price = bar_product_price.render_embed()

    return render_template("summary.html", chart_product_count=chart_product_count, chart_product_price=chart_product_price)

# Defining a host as shown below is necessary for replit, not needed if we're building our project on a local system
# 0.0.0.0 means that our app accepts requests from any server
app.run(host  = "0.0.0.0", debug = True)