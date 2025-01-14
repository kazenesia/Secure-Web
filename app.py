from flask import Flask, render_template, redirect, url_for, request, session, flash
from functools import wraps
import uuid
import datetime
import secrets

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Simulasi database
users = {
    'superadmin': {'password': 'superpassword', 'role': 'superadmin', 'uuid': str(uuid.uuid4()), 'token': secrets.token_urlsafe(16)}
}
logs = []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('You need to login first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'superadmin':
            flash('You do not have access to this page.')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and user['password'] == password:
            session['logged_in'] = True
            session['username'] = username
            session['role'] = user['role']
            session['uuid'] = user['uuid']
            session['token'] = user['token']
            return redirect(url_for('dashboard', token=user['token']))
        flash('Invalid login credentials.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'user'  # Default role
        user_uuid = str(uuid.uuid4())
        user_token = secrets.token_urlsafe(16)
        if username in users:
            flash('Username already exists.')
        else:
            users[username] = {'password': password, 'role': role, 'uuid': user_uuid, 'token': user_token}
            flash('User created successfully.')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard/<token>')
@login_required
def dashboard(token):
    if token != session.get('token'):
        flash('Unauthorized access.')
        return redirect(url_for('login'))
    return render_template('dashboard.html', token=token, role=session['role'], username=session['username'])

@app.route('/profile/<token>')
@login_required
def profile(token):
    if token != session.get('token'):
        flash('Unauthorized access.')
        return redirect(url_for('login'))
    return render_template('profile.html', token=token, role=session['role'], username=session['username'])

@app.route('/logs/<token>')
@superadmin_required
def log_data(token):
    if token != session.get('token'):
        flash('Unauthorized access.')
        return redirect(url_for('login'))
    return render_template('logs.html', logs=logs, token=token, role=session['role'], username=session['username'])

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.before_request
def log_everything():
    if 'username' in session:
        logs.append({
            'uuid': str(uuid.uuid4()),
            'key': 'intruder' if request.endpoint not in app.view_functions else 'httpaccess',
            'txt': request.path,
            'session': session['role'],
            'ip': request.remote_addr,
            'app': 'FlaskApp',
            'time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

if __name__ == '__main__':
    app.run(debug=True)
