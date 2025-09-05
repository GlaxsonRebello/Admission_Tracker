import os

MYSQL_HOST = 'localhost'
MYSQL_USER = 'admission_app'
MYSQL_PASSWORD = '12345'
MYSQL_DB = 'admission_tracker'
MYSQL_CURSORCLASS = 'DictCursor'
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallbacksecret')
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'   # 'Strict' if your flows allow
SESSION_COOKIE_SECURE = False     # True in production over HTTPS
PERMANENT_SESSION_LIFETIME = 60*60*4  # 4 hours
