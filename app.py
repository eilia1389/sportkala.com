from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    UserMixin, current_user
)

# 🔹 تنظیمات اولیه
app = Flask(__name__)
app.config['SECRET_KEY'] = 'eilia_secret_key_2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///e.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🔹 راه‌اندازی افزونه‌ها
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 🔹 مدل کاربر
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 🔹 مسیرهای عمومی
@app.route("/")
@app.route("/index")
def home():
    return render_template("index.html", user=current_user)

@app.route("/m")
def store():
    return render_template("m.html", user=current_user)

@app.route("/h")
def about():
    return render_template("h.html", user=current_user)

@app.route("/call with us")
def call():
    return render_template("callwithus.html", user=current_user)

@app.route("/index3")
def shoes():
    return render_template("index3.html")

@app.route("/index4")
def ball():
    return render_template("index4.html")

@app.route("/index5")
def domble():
    return render_template("index5.html")

@app.route("/index6")
def bag():
    return render_template("index6.html")

@app.route("/index7")
def bootle():
    return render_template("index7.html")

@app.route("/index8")
def ract():
    return render_template("index8.html")

# 🔹 ثبت‌نام کاربر
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if not username or not email or not password:
            flash("لطفاً همه فیلدها را پر کنید", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(username=username).first():
            flash("نام کاربری قبلاً ثبت شده", "danger")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("ایمیل قبلاً ثبت شده", "danger")
            return redirect(url_for("signup"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f"خطا در ثبت نام: {e}", "danger")
            return redirect(url_for("signup"))

        login_user(new_user)  # ورود خودکار
        flash("ثبت‌نام موفق بود، خوش آمدید!", "success")
        return redirect(url_for("home"))

    return render_template("signup.html", user=current_user)

# 🔹 ورود کاربر
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("ورود موفقیت‌آمیز بود", "success")
            return redirect(url_for("home"))
        else:
            flash("نام کاربری یا رمز عبور اشتباه است", "danger")
            return redirect(url_for("login"))

    return render_template("login.html", user=current_user)

# 🔹 خروج از حساب
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("با موفقیت خارج شدید", "info")
    return redirect(url_for("login"))

# 🔹 ساخت جدول‌ها
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
