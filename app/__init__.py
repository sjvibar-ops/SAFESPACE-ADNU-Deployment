import os
import logging
from logging.handlers import RotatingFileHandler, SMTPHandler

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config

# Create app
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

login.login_view = 'auth.login_signup'
login.session_protection = 'strong'

# Import after app/db created to avoid circular imports
from app import routes, models, errors

# Register blueprints (from routes.py)
from app.routes import auth_bp, user_bp, therapist_bp, chat_bp
app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)
app.register_blueprint(therapist_bp)
app.register_blueprint(chat_bp)

# Register error handlers (from errors.py)
from app.errors import not_found_error, forbidden_error, internal_error
app.register_error_handler(404, not_found_error)
app.register_error_handler(403, forbidden_error)
app.register_error_handler(500, internal_error)

if not app.debug:
    # File logging ALWAYS runs in production
    if not os.path.exists('logs'):
        os.mkdir('logs')

    file_handler = RotatingFileHandler(
        'logs/safespace.log',
        maxBytes=10240,
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    # Email logging ONLY if mail server configured
    if app.config.get('MAIL_SERVER'):
        auth = None
        if app.config.get('MAIL_USERNAME') or app.config.get('MAIL_PASSWORD'):
            auth = (app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        secure = None
        if app.config.get('MAIL_USE_TLS'):
            secure = ()

        mail_handler = SMTPHandler(
            mailhost=(app.config['MAIL_SERVER'], app.config['MAIL_PORT']),
            fromaddr='no-reply@' + app.config['MAIL_SERVER'],
            toaddrs=app.config.get('ADMINS', []),
            subject='SafeSpace Application Error',
            credentials=auth,
            secure=secure
        )
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('SafeSpace startup')


