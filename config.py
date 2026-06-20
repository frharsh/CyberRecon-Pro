"""
CyberRecon Pro - Configuration
"""
import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    WTF_CSRF_ENABLED = True

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(BASE_DIR, 'database', 'database.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Upload / Storage paths
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    SCREENSHOTS_DIR = os.path.join(BASE_DIR, 'screenshots')
    STATIC_DIR = os.path.join(BASE_DIR, 'static')

    # App settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB upload limit
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # Tool paths (override via environment variables if needed)
    NMAP_PATH    = os.environ.get('NMAP_PATH', 'nmap')
    SUBFINDER_PATH = os.environ.get('SUBFINDER_PATH', 'subfinder')
    AMASS_PATH   = os.environ.get('AMASS_PATH', 'amass')
    FFUF_PATH    = os.environ.get('FFUF_PATH', 'ffuf')
    WHATWEB_PATH = os.environ.get('WHATWEB_PATH', 'whatweb')

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
