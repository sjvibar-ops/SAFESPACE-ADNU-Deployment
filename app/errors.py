from flask import render_template
from app import app, db

def not_found_error(error):
    return render_template('errors/404.html'), 404

def forbidden_error(error):
    return render_template('errors/403.html'), 403

def internal_error(error):
    db.session.rollback()
    app.logger.exception("Unhandled 500 error")
    return render_template('errors/500.html'), 500