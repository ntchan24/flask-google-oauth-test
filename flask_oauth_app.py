from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
import os
from functools import wraps

app = Flask(__name__)

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

# OAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user' in session:
        user = session['user']
        return f'''
        <h1>Welcome to Flask Google OAuth Test</h1>
        <h2>Hello, {user['name']}!</h2>
        <p><strong>Email:</strong> {user['email']}</p>
        <p><strong>Google ID:</strong> {user['sub']}</p>
        <img src="{user['picture']}" alt="Profile Picture" style="border-radius: 50%; width: 100px;">
        <br><br>
        <a href="/profile">View Full Profile</a> | 
        <a href="/logout">Logout</a>
        '''
    else:
        return '''
        <h1>Flask Google OAuth Test</h1>
        <p>You are not logged in.</p>
        <a href="/login">Login with Google</a>
        '''

@app.route('/login')
def login():
    # Generate a random nonce for security
    nonce = os.urandom(16).hex()
    session['nonce'] = nonce
    
    # Generate a random state for CSRF protection
    state = os.urandom(16).hex()
    session['oauth_state'] = state
    
    redirect_uri = url_for('callback', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce, state=state)

@app.route('/callback')
def callback():
    try:
        # Verify state parameter
        state = request.args.get('state')
        if not state or state != session.get('oauth_state'):
            return 'Invalid state parameter', 400
            
        token = google.authorize_access_token()
        nonce = session.pop('nonce', None)
        session.pop('oauth_state', None)  # Clean up state after use
        
        # Get user info using the access token
        resp = google.get('https://openidconnect.googleapis.com/v1/userinfo', token=token)
        user_info = resp.json()
        
        if user_info:
            session['user'] = user_info
            return redirect(url_for('index'))
        else:
            return 'Failed to get user info from Google', 400
            
    except Exception as e:
        return f'Error during authentication: {str(e)}', 400

@app.route('/profile')
@login_required
def profile():
    user = session['user']
    return jsonify(user)

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('nonce', None)
    return redirect(url_for('index'))

@app.route('/health')
def health():
    return {'status': 'healthy', 'oauth_configured': bool(app.config['GOOGLE_CLIENT_ID'])}

if __name__ == '__main__':
    # Check if required environment variables are set
    if not app.config['GOOGLE_CLIENT_ID'] or not app.config['GOOGLE_CLIENT_SECRET']:
        print("WARNING: Google OAuth credentials not found!")
        print("Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables")
    
    app.run(debug=True, port=5000)