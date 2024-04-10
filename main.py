from flask import Flask, render_template,flash, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
# from functions.login_functions import login_user
# from functions.register_functions import register_user
from flask_migrate import Migrate
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from datetime import datetime
import json
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:123QWEasdzxc@localhost/books'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'unikalny_sekretny_klucz'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
json_file_path = 'books_data.json'


# Model dla tabeli Book
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    year = db.Column(db.Integer, nullable=False)


class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=True) 
    book = db.relationship('Book', backref=db.backref('purchases', lazy=True))
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.Text, nullable=False)
    city = db.Column(db.String(50), nullable=False)
    postal_code = db.Column(db.String(10), nullable=False)
    purchase_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    birth_date = db.Column(db.Date, nullable=True)


users = {"admin": {"password": bcrypt.generate_password_hash("admin_password").decode('utf-8')}}


@app.route('/')
def home():
    categories = ["horror", "fantasy", "comedy", "thriller", "Historical novel", "Romance"]
    search_query = request.args.get('search', '')

    filtered_books = Book.query.filter(Book.title.ilike(f"%{search_query}%")).all()
    titles = set(book.title for book in filtered_books)
    return render_template('home.html', categories=categories, books=filtered_books, titles=titles, session=session)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == 'admin' and password == 'admin_password':
            session['admin_logged_in'] = True
            return redirect(url_for('admin_panel'))

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            session['username'] = user.username

            flash('You have logged in successfully.', 'success')
            return redirect(url_for('home'))

        else:
            flash('Incorrect username or password.', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone_number = request.form['phone_number']
        birth_date = request.form['birth_date']

        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash('The username is already taken.', 'danger')
            return redirect(url_for('register'))

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('The email address is already in use.', 'danger')
            return redirect(url_for('register'))

        existing_phone_number = User.query.filter_by(phone_number=phone_number).first()
        if existing_phone_number:
            flash('The phone number is already in use.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 6 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password) or not any(char.isalnum() for char in password):
            flash('The password must be at least 6 characters long and contain at least one number, letter and special character.', 'danger')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            username=username,
            password=hashed_password,
            email=email,
            phone_number=phone_number,
            birth_date=birth_date
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration completed successfully! You can log in now.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred during registration. try again.', 'danger')

    return render_template('register.html')

@app.route('/logout')
def logout():

    session.pop('logged_in', None)
    session.pop('admin_logged_in', None)

    return redirect(url_for('logout_message'))


@app.route('/logout_message')
def logout_message():
    return render_template('logout_message.html')


@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    # Kod obsługi panelu administratora
    search_query = request.args.get('search', '')

    filtered_books = Book.query.filter(Book.title.ilike(f"%{search_query}%")).all()
    titles = set(book.title for book in filtered_books)
    return render_template('admin_panel.html', books=filtered_books, titles=titles, session=session)


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))


@app.route('/admin/delete_book', methods=['POST'])
def admin_delete_book():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    book_title = request.form.get('book_title')
    delete_book_from_db(book_title)
    update_books_json()
    return redirect(url_for('admin_panel'))




@app.route('/admin/edit_book', methods=['GET', 'POST'])
def admin_edit_book():
    if request.method == 'GET':
        book_title = request.args.get('book_title_edit')
        if book_title:
            book = Book.query.filter_by(title=book_title).first()
            if book:
                return redirect(url_for('edit_book', title=book.title))
            else:
                flash('No book with the given title was found.', 'danger')
                return redirect(url_for('admin_panel'))
        else:
            flash('No title of the book to be edited was given.', 'danger')
            return redirect(url_for('admin_panel'))


@app.route('/admin/manage_user', methods=['POST'])
def manage_user():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))

    username = request.form.get('username')
    action = request.form.get('action')

    if action == 'ban':
        return redirect(url_for('admin_panel'))
    elif action == 'delete':
        return redirect(url_for('admin_panel'))
    else:
        return "Nieprawidłowa akcja"


@app.route('/category/<category_name>')
def show_category(category_name):
    category_books = Book.query.filter_by(category=category_name).all()
    return render_template('category.html', category_name=category_name, category_books=category_books)


def save_user_to_db(user_data):
    with app.app_context():
        new_user = User(
            first_name=user_data['first_name'],
            last_name=user_data['last_name'],
            username=user_data['username'],
            password=user_data['password'],
            email=user_data['email'],
            phone_number=user_data['phone_number'],
            birth_date=user_data['birth_date']
        )
        db.session.add(new_user)
        db.session.commit()


def save_books_to_json(books):
    with open(json_file_path, 'w') as json_file:
        json.dump(books, json_file, default=str)


def load_books_from_json():
    if os.path.exists(json_file_path):
        with open(json_file_path, 'r') as json_file:
            return json.load(json_file)
    return []


def save_book_to_db(book_data):
    with app.app_context():
        new_book = Book(
            title=book_data['title'],
            author=book_data['author'],
            price=book_data['price'],
            category=book_data['category'],
            description=book_data['description'],
            year=book_data['year']
        )
        db.session.add(new_book)
        db.session.commit()


def update_books_json():
    books = load_books_from_db()
    books_data = [{'title': book.title, 'author': book.author, 'price': book.price, 'category': book.category,
                   'description': book.description, 'year': book.year} for book in books]
    save_books_to_json(books_data)


def delete_book_from_db(title):
    with app.app_context():
        book_to_delete = Book.query.filter_by(title=title).first()
        db.session.delete(book_to_delete)
        db.session.commit()


def load_books_from_db():
    with app.app_context():
        return Book.query.all()


def update_book_in_db(title, new_data):
    with app.app_context():
        book_to_update = Book.query.filter_by(title=title).first()
        if book_to_update:
            book_to_update.title = new_data['title']
            book_to_update.author = new_data['author']
            book_to_update.price = new_data['price']
            book_to_update.category = new_data['category']
            book_to_update.description = new_data['description']
            book_to_update.year = new_data['year']
            db.session.commit()
            update_books_json()


def load_books_data():
    books = load_books_from_json()
    with app.app_context():
        for book_data in books:
            new_book = Book(
                title=book_data['title'],
                author=book_data['author'],
                price=book_data['price'],
                category=book_data['category'],
                description=book_data['description'],
                year=book_data['year']
            )
            db.session.add(new_book)
        db.session.commit()


@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_book = {
            "title": request.form['title'],
            "author": request.form['author'],
            "price": float(request.form['price']),
            "category": request.form['category'],
            "description": request.form['description'],
            "year": int(request.form['year'])
        }
        save_book_to_db(new_book)
        update_books_json()
        return redirect(url_for('home'))
    return render_template('add_book.html')


@app.route('/buy_message')
def buy_message():
    return render_template('buy_message.html')


@app.route('/buy_book/<int:book_id>', methods=['GET', 'POST'])
def buy_book(book_id):
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        city = request.form.get('city')
        postal_code = request.form.get('postal_code')

        book = Book.query.get_or_404(book_id)

        purchase = Purchase(
            book=book,
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone_number=phone_number,
            address=address,
            city=city,
            postal_code=postal_code
        )

        db.session.add(purchase)
        db.session.commit()

        db.session.delete(book)
        db.session.commit()

        return redirect(url_for('buy_message'))

    book = Book.query.get_or_404(book_id)
    return render_template('buy_book.html', book=book)


@app.route('/delete_book/<title>', methods=['POST'])
def delete_book(title):
    if not session.get('logged_in'):
        flash('You must be logged in to delete a book.', 'danger')
        return redirect(url_for('login'))

    delete_book_from_db(title)
    flash(f'Book "{title}" has been deleted.', 'success')
    return redirect(url_for('books_list'))


@app.route('/books_list')
def books_list():
    books = load_books_from_db()
    return render_template('books_list.html', books=books)


@app.route('/edit_book/<title>', methods=['GET', 'POST'])
def edit_book(title):
    if request.method == 'POST':
        updated_book_data = {
            "title": request.form['title'],
            "author": request.form['author'],
            "price": float(request.form['price']),
            "category": request.form['category'],
            "description": request.form['description'],
            "year": int(request.form['year'])
        }
        update_book_in_db(title, updated_book_data)
        return redirect(url_for('home'))

    book_to_edit = Book.query.filter_by(title=title).first()

    return render_template('edit_book.html', book=book_to_edit)


if __name__ == '__main__':
    with app.app_context():
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()

        if 'book' not in tables:
            db.create_all()
            load_books_data()
        if 'user' not in tables:
            db.create_all()
        if 'purchase' not in tables:
            db.create_all()
    app.run(debug=True)
