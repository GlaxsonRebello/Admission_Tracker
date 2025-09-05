from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask import g
import MySQLdb.cursors
import datetime
import ipaddress


# App Setup
app = Flask(__name__)
csrf = CSRFProtect(app)  # Add CSRF protection to all forms
app.config.from_pyfile("config.py")
limiter = Limiter(get_remote_address, app=app, default_limits=["200/day", "50/hour"])

mysql = MySQL(app)
bcrypt = Bcrypt(app)

csp = {
  'default-src': "'self'",
  'style-src':   "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
  'script-src':  "'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
}
Talisman(app, content_security_policy=csp, force_https=False)  # set True when behind HTTPS

def ip_to_bytes(ip):
    return ipaddress.ip_address(ip).packed

def too_many_recent_failures(email):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT SUM(success=0) AS fails
        FROM login_attempts
        WHERE email=%s AND created_at > NOW() - INTERVAL 15 MINUTE
    """, [email])
    row = cursor.fetchone()
    return (row['fails'] or 0) >= 5

@app.before_request
def log_hit():
    # Skip static assets to keep the table clean
    if request.path.startswith('/static'):
        return
    try:
        ip_bytes = ipaddress.ip_address(request.remote_addr).packed
    except Exception:
        ip_bytes = None
    uid = session.get('id') if session.get('loggedin') else None
    ua = request.headers.get('User-Agent', '')[:255]

    cursor = mysql.connection.cursor()
    cursor.execute("""
        INSERT INTO web_hits(path, method, ip, user_agent, user_id)
        VALUES (%s,%s,%s,%s,%s)
    """, (request.path[:255], request.method, ip_bytes, ua, uid))
    mysql.connection.commit()

@app.route('/admin/hits')
def admin_hits():
    if 'loggedin' in session and session['role']=='admin':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM v_hit_counts")
        rows = cursor.fetchall()
        return render_template('admin_hits.html', rows=rows)
    return redirect(url_for('login'))


# --------------------------
# Home (Login Page)
# --------------------------
@app.route('/', methods=['GET','POST'])
@limiter.limit("5/minute; 20/hour")
def login():
    if request.method == 'POST':
        role = request.form['role']
        email = request.form['email']
        password = request.form['password']

        if too_many_recent_failures(email):
            flash("Too many failed attempts. Try again in 15 minutes.")
            return render_template('login.html')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE email=%s AND role=%s", (email, role))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password'], password):
            session['loggedin'] = True
            session['id'] = user['id']
            session['role'] = user['role']
            if role == 'student':
                return redirect(url_for('student_dashboard'))
            else:
                return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid login details")
    return render_template('login.html')


# --------------------------
# Student Registration
# --------------------------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash("Passwords do not match")
            return redirect(url_for('register'))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE email=%s", [email])
        account = cursor.fetchone()
        if account:
            flash("Email already registered")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        cursor.execute("INSERT INTO users (name,email,password,role) VALUES (%s,%s,%s,'student')", (name,email,hashed_pw))
        mysql.connection.commit()
        flash("Registration successful. Please login.")
        return redirect(url_for('login'))

    return render_template('register.html')


# --------------------------
# Student Dashboard
# --------------------------
@app.route('/student/dashboard')
def student_dashboard():
    if 'loggedin' in session and session['role']=='student':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM admissions WHERE student_id=%s", [session['id']])
        admission = cursor.fetchone()
        return render_template('student_dashboard.html', admission=admission)
    return redirect(url_for('login'))


# --------------------------
# Apply for Admission (POST only now)
# --------------------------
@app.route('/student/apply', methods=['POST'])
def apply_admission():
    if 'loggedin' in session and session['role']=='student':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("INSERT INTO admissions (student_id) VALUES (%s)", [session['id']])
        mysql.connection.commit()
        flash("Admission form submitted successfully!")
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))


# --------------------------
# Admin Dashboard
# --------------------------
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'loggedin' in session and session['role']=='admin':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT admissions.id, users.name, users.email, 
                   admissions.form_status, admissions.payment_status, 
                   admissions.registered_at, admissions.form_updated_at, admissions.payment_updated_at 
            FROM admissions 
            JOIN users ON admissions.student_id=users.id
        """)
        students = cursor.fetchall()
        return render_template('admin_dashboard.html', students=students)
    return redirect(url_for('login'))


# --------------------------
# Admin Update (POST only now)
# --------------------------
# --------------------------
# Admin Update (POST only, safer with try/except)
# --------------------------
@app.route('/admin/update/<int:admission_id>', methods=['POST'])
@limiter.limit("10/minute")
def update_admission(admission_id):
    if 'loggedin' in session and session['role'] == 'admin':
        action = request.form.get('action')
        note = request.form.get('note', '')[:255]

        try:
            cursor = mysql.connection.cursor()
            cursor.callproc('sp_admin_update_admission', (
                admission_id, action, session['id'], note
            ))
            mysql.connection.commit()
            flash("Action performed successfully")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Error: {str(e)}")

        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

# --------------------------
# Logout
# --------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
