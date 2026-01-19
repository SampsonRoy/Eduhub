from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from paystack import Transaction

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "change_this_secret_key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eduhub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), "uploads")
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "sk_test_your_secret_key")
paystack_transaction = Transaction(secret_key=PAYSTACK_SECRET_KEY)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_lecturer = db.Column(db.Boolean, default=False)

class PastQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    university = db.Column(db.String(100))
    preview = db.Column(db.Text)
    file_path = db.Column(db.String(200))

class PremiumNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    price = db.Column(db.Float)
    description = db.Column(db.Text)
    file_path = db.Column(db.String(200))
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    note_id = db.Column(db.Integer, db.ForeignKey('premium_note.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    past_qs = PastQuestion.query.limit(5).all()
    notes = PremiumNote.query.limit(5).all()
    return render_template('home.html', past_qs=past_qs, notes=notes, cart_count=len(session.get('cart', [])))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        if User.query.filter_by(email=email).first():
            flash("Email already registered")
            return redirect(url_for('register'))
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        is_lecturer = 'is_lecturer' in request.form
        new_user = User(email=email, password=password, is_lecturer=is_lecturer)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Account created!')
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/past-questions')
def past_questions():
    qs = PastQuestion.query.all()
    return render_template('past_questions.html', qs=qs)

@app.route('/past-question/<int:id>')
def past_question(id):
    q = PastQuestion.query.get_or_404(id)
    return render_template('past_question.html', q=q)

@app.route('/premium-notes')
def premium_notes():
    notes = PremiumNote.query.all()
    return render_template('premium_notes.html', notes=notes)

@app.route('/add-to-cart/<int:id>')
@login_required
def add_to_cart(id):
    cart = session.get('cart', [])
    if id not in cart:
        cart.append(id)
    session['cart'] = cart
    flash('Added to cart')
    return redirect(url_for('premium_notes'))

@app.route('/cart')
@login_required
def cart():
    cart_ids = session.get('cart', [])
    notes = PremiumNote.query.filter(PremiumNote.id.in_(cart_ids)).all()
    total = sum(n.price for n in notes)
    return render_template('cart.html', notes=notes, total=total)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    if not cart_ids:
        return redirect(url_for('cart'))
    notes = PremiumNote.query.filter(PremiumNote.id.in_(cart_ids)).all()
    total = int(sum(n.price for n in notes) * 100)
    try:
        response = paystack_transaction.initialize(
            email=current_user.email,
            amount=total,
            currency='GHS',
            reference=f'ref_{current_user.id}_{os.urandom(4).hex()}'
        )
        if response['status']:
            return redirect(response['data']['authorization_url'])
    except Exception as e:
        flash(f'Payment initialization failed: {e}')
    return redirect(url_for('cart'))

@app.route('/payment-callback')
@login_required
def payment_callback():
    ref = request.args.get('reference')
    try:
        response = paystack_transaction.verify(ref)
        if response['status'] and response['data']['status'] == 'success':
            cart_ids = session.pop('cart', [])
            for note_id in cart_ids:
                purchase = Purchase(user_id=current_user.id, note_id=note_id)
                db.session.add(purchase)
            db.session.commit()
            flash('Payment successful!')
            return redirect(url_for('account'))
    except Exception as e:
        flash(f'Payment failed: {e}')
    return redirect(url_for('cart'))

@app.route('/account')
@login_required
def account():
    purchases = Purchase.query.filter_by(user_id=current_user.id).all()
    notes = [PremiumNote.query.get(p.note_id) for p in purchases]
    return render_template('account.html', notes=notes)

@app.route('/download/<int:id>')
@login_required
def download(id):
    purchase = Purchase.query.filter_by(user_id=current_user.id, note_id=id).first()
    if purchase:
        note = PremiumNote.query.get(id)
        return send_file(note.file_path, as_attachment=True)
    flash('Not authorized')
    return redirect(url_for('account'))

@app.route('/lecturer-upload', methods=['GET', 'POST'])
@login_required
def lecturer_upload():
    if not current_user.is_lecturer:
        flash('Only lecturers can upload')
        return redirect(url_for('home'))
    if request.method == 'POST':
        title = request.form['title']
        price = float(request.form['price'])
        description = request.form['description']
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            new_note = PremiumNote(title=title, price=price, description=description,
                                   file_path=file_path, uploader_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Uploaded successfully')
        return redirect(url_for('account'))
    return render_template('upload.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        flash('Message sent')
    return render_template('contact.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

if __name__ == '__main__':
    app.run(debug=True)