from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
import click

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-please-change')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///formal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuration
MAX_CAPACITY = 200  # Maximum number of attendees (including plus ones)

# Template context processor
@app.context_processor
def inject_year():
    return {'now': datetime.utcnow()}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    name = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    registration = db.relationship('Registration', backref='user', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    registration_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    plus_one_name = db.Column(db.String(100))
    waitlist_position = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), default='registered')  # 'registered' or 'waitlisted'
    payment_confirmed = db.Column(db.Boolean, default=False)
    payment_amount = db.Column(db.Float, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def update_waitlist():
    # Get all waitlisted registrations ordered by registration date
    waitlist = Registration.query.filter_by(status='waitlisted').order_by(Registration.registration_date).all()
    
    # Update positions
    for index, registration in enumerate(waitlist, 1):
        registration.waitlist_position = index
    
    db.session.commit()

@app.route('/')
def index():
    total_registrations = Registration.query.filter_by(status='registered').count()
    available_spots = MAX_CAPACITY - total_registrations
    return render_template('index.html', available_spots=available_spots)

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if current_user.registration:
        flash('You are already registered for the event.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        plus_one_name = request.form.get('plus_one_name')
        payment_confirmation = request.form.get('payment_confirmation') == 'on'
        bringing_plus_one = request.form.get('bringing_plus_one') == 'on'
        
        # Calculate payment amount
        base_amount = 15
        plus_one_amount = 50 if bringing_plus_one else 0
        total_amount = base_amount + plus_one_amount
        
        if not payment_confirmation:
            flash('Please confirm that you have sent the Venmo payment.')
            return redirect(url_for('register'))
        
        # Check if we're at capacity
        total_registrations = Registration.query.filter_by(status='registered').count()
        
        registration = Registration(
            user_id=current_user.id,
            plus_one_name=plus_one_name if bringing_plus_one else None,
            status='registered' if total_registrations < MAX_CAPACITY else 'waitlisted',
            payment_confirmed=payment_confirmation,
            payment_amount=total_amount
        )
        
        db.session.add(registration)
        db.session.commit()
        
        if registration.status == 'waitlisted':
            update_waitlist()
            flash('Event is at capacity. You have been added to the waitlist. Your payment will only be required if a spot becomes available.')
        else:
            flash('Successfully registered for the event! Please note that your registration will be confirmed after payment verification.')
            
        return redirect(url_for('dashboard'))
        
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('signup'))
            
        user = User(email=email, name=name)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Successfully registered! Please login.')
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.cli.command("list-users")
def list_users():
    """List all registered users"""
    users = User.query.all()
    click.echo("\nRegistered Users:")
    click.echo("-" * 80)
    click.echo(f"{'ID':<5} {'Name':<20} {'Email':<30} {'Registration Status':<20}")
    click.echo("-" * 80)
    for user in users:
        status = "Not Registered"
        if user.registration:
            status = user.registration.status.capitalize()
        click.echo(f"{user.id:<5} {user.name:<20} {user.email:<30} {status:<20}")

@app.cli.command("list-registrations")
def list_registrations():
    """List all event registrations"""
    registrations = Registration.query.order_by(Registration.registration_date).all()
    click.echo("\nEvent Registrations:")
    click.echo("-" * 100)
    click.echo(f"{'ID':<5} {'User':<20} {'Status':<12} {'Waitlist#':<10} {'Plus One':<20} {'Date':<20}")
    click.echo("-" * 100)
    for reg in registrations:
        waitlist = str(reg.waitlist_position) if reg.waitlist_position else "N/A"
        plus_one = reg.plus_one_name if reg.plus_one_name else "None"
        click.echo(f"{reg.id:<5} {reg.user.name:<20} {reg.status:<12} {waitlist:<10} {plus_one:<20} {reg.registration_date.strftime('%Y-%m-%d %H:%M'):<20}")

# Admin required decorator
def admin_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/admin')
@admin_required
def admin_dashboard():
    total_registrations = Registration.query.filter_by(status='registered').count()
    waitlist_count = Registration.query.filter_by(status='waitlisted').count()
    available_spots = MAX_CAPACITY - total_registrations
    pending_payments = Registration.query.filter_by(status='registered', payment_confirmed=False).count()
    
    # Get recent registrations
    recent_registrations = Registration.query.order_by(Registration.registration_date.desc()).limit(5).all()
    
    # Get waitlist
    waitlist = Registration.query.filter_by(status='waitlisted').order_by(Registration.registration_date).all()
    
    return render_template('admin/dashboard.html',
                         total_registrations=total_registrations,
                         waitlist_count=waitlist_count,
                         available_spots=available_spots,
                         pending_payments=pending_payments,
                         recent_registrations=recent_registrations,
                         waitlist=waitlist)

@app.route('/admin/registrations')
@admin_required
def admin_registrations():
    registrations = Registration.query.order_by(Registration.registration_date.desc()).all()
    
    # Calculate payment totals
    total_verified_amount = sum(reg.payment_amount for reg in registrations if reg.payment_confirmed and reg.status == 'registered')
    total_pending_amount = sum(reg.payment_amount for reg in registrations if not reg.payment_confirmed and reg.status == 'registered')
    
    return render_template('admin/registrations.html',
                         registrations=registrations,
                         total_verified_amount=total_verified_amount,
                         total_pending_amount=total_pending_amount)

@app.route('/admin/waitlist')
@admin_required
def admin_waitlist():
    waitlist = Registration.query.filter_by(status='waitlisted').order_by(Registration.registration_date).all()
    return render_template('admin/waitlist.html', waitlist=waitlist)

@app.route('/admin/remove-registration/<int:registration_id>', methods=['POST'])
@admin_required
def remove_registration(registration_id):
    registration = Registration.query.get_or_404(registration_id)
    
    # If removing a registered user, promote the first waitlisted person
    if registration.status == 'registered':
        first_waitlisted = Registration.query.filter_by(status='waitlisted').order_by(Registration.registration_date).first()
        if first_waitlisted:
            first_waitlisted.status = 'registered'
            first_waitlisted.waitlist_position = None
            flash(f'Promoted {first_waitlisted.user.name} from waitlist to registered.')
    
    db.session.delete(registration)
    db.session.commit()
    
    # Update waitlist positions
    update_waitlist()
    
    flash('Registration removed successfully.')
    return redirect(url_for('admin_registrations'))

@app.route('/admin/toggle-payment/<int:registration_id>', methods=['POST'])
@admin_required
def toggle_payment_verification(registration_id):
    registration = Registration.query.get_or_404(registration_id)
    registration.payment_confirmed = not registration.payment_confirmed
    db.session.commit()
    
    action = "verified" if registration.payment_confirmed else "unverified"
    flash(f'Payment {action} for {registration.user.name}')
    return redirect(url_for('admin_registrations'))

@app.cli.command("create-admin")
@click.argument('email')
@click.argument('name')
@click.password_option()
def create_admin(email, name, password):
    """Create a new admin user"""
    if User.query.filter_by(email=email).first():
        click.echo('Error: Email already registered')
        return
    
    user = User(email=email, name=name, is_admin=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f'Admin user {name} created successfully')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 