from flask import Blueprint, render_template, request, redirect, url_for, session
from datetime import datetime, timedelta
from .utils import *
import io
import base64
import pyotp
import qrcode
import bcrypt

bp = Blueprint('main', __name__)

@bp.route('/')
def home():
    return redirect('/static/index.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    # return login page on GET
    if request.method == "GET":
        return redirect("/static/login.html")
    # process login on POST
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # open connection to DB
        conn = get_db_connection()
        cursor = conn.cursor()
        # fetch user record including lockout info
        cursor.execute(
            "SELECT user_id, username, password_hash, totp_secret, failed_login_attempts, lockout_until FROM users WHERE username=%s",
            (username,),
        )
        # get the one record that is returned, should only be one
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        # if no user found, close connection and return generic error
        if not user:
            return render_template('error.html', error_message="Invalid credentials", error_code=401)

        # unpack user record
        user_id, username, password_hash, totp_secret, failed_attempts, lockout_until = user

        # if account is currently locked, check timestamp
        if lockout_until is not None:
            try:
                # lockout_until is expected to be a datetime object from DB
                if isinstance(lockout_until, datetime) and lockout_until > datetime.utcnow():
                    return render_template('error.html', error_message=f"Account locked until {lockout_until} UTC", error_code=403)
            except Exception:
                # if any unexpected value, continue and treat normally
                pass

        # verify password
        if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
            # increment failed attempts and optionally set lockout
            failed_attempts = (failed_attempts or 0) + 1
            LOCKOUT_THRESHOLD = 3
            LOCKOUT_SECONDS = 5 * 60  # 5 minutes lockout
            if failed_attempts >= LOCKOUT_THRESHOLD:
                conn = get_db_connection()
                cursor = conn.cursor()
                new_lockout = datetime.utcnow() + timedelta(seconds=LOCKOUT_SECONDS)
                # reset counter and set lockout
                cursor.execute(
                    "UPDATE users SET failed_login_attempts=%s, lockout_until=%s WHERE user_id=%s",
                    (0, new_lockout, user_id),
                )
                conn.commit()
                cursor.close()
                conn.close()
                return render_template('error.html', error_message=f"Too many failed attempts. Account locked until {new_lockout} UTC", error_code=403)
            else:
                # just update failed attempts
                cursor.execute(
                    "UPDATE users SET failed_login_attempts=%s WHERE user_id=%s",
                    (failed_attempts, user_id),
                )
                conn.commit()
                cursor.close()
                conn.close()
                return render_template('error.html', error_message="Invalid credentials", error_code=401)

        # passed password check: reset failed counters and clear lockout
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET failed_login_attempts=%s, lockout_until=%s WHERE user_id=%s",
            (0, None, user_id),
        )
        conn.commit()
        # close connection
        cursor.close()
        conn.close()

        # store user info for OTP verification
        session["pre_otp_user_id"] = user_id
        session["pre_otp_username"] = username
        session["pre_otp_secret"] = totp_secret
        # send user to OTP verification page
        return render_template("verify_otp.html")

@bp.route("/verify_otp", methods=["POST"])
def verify_otp():
    # grab the OTP code from the form
    otp_input = request.form.get("otp")
    # along with the session info
    user_id = session.get("pre_otp_user_id")
    username = session.get("pre_otp_username")
    secret = session.get("pre_otp_secret")
    # validate session info
    if not user_id:
        return render_template('error.html', error_message="Session expired or invalid", error_code=401)
    # validate OTP
    # done by recreating the TOTP object with the stored secret
    totp = pyotp.TOTP(secret)
    # verify the input OTP against the generated one
    if not totp.verify(otp_input):
        # if not a match, return error
        return render_template('error.html', error_message="Invalid OTP", error_code=401)
    # more explicit on the successful OTP verification
    else:
        # passed OTP check!
        # prep work for dashboard
        # clear the temp session info
        session.pop("pre_otp_user_id", None)
        session.pop("pre_otp_username", None)
        session.pop("pre_otp_secret", None)
        # fetch user access level
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT access_level FROM users WHERE user_id=%s", (user_id,))
        access_level = cursor.fetchone()[0]
        # update last_login to now (UTC)
        try:
            cursor.execute("UPDATE users SET last_login=%s WHERE user_id=%s", (datetime.utcnow(), user_id))
            conn.commit()
        except Exception:
            conn.rollback()
        # proper session info now
        session["user_id"] = user_id
        session["username"] = username
        session["access_level"] = access_level
        # Fetch passwords visible to user (own entries + those below access level)
        cursor.execute("""
            SELECT p.password_id, p.category_id, p.service_name, p.login_username, CAST(AES_DECRYPT(password_encrypted, %s) AS CHAR(255)) AS password_encrypted, p.notes, p.min_access_level, p.created_at, p.updated_at
            FROM passwords p
            WHERE p.min_access_level <= %s;
        """, (os.getenv("PSW_KEY"), session["access_level"]))
        rows = cursor.fetchall()
        cols = [desc[0] for desc in cursor.description]
        passwords = [dict(zip(cols, row)) for row in rows]
        cursor.close()
        conn.close()
        # render dashboard
        return render_template("dashboard.html", user_id=user_id, username=username, access_level=access_level, passwords=passwords)

@bp.route('/dashboard')
def dashboard():
    # get session info
    user_id = session.get("user_id")
    username = session.get("username")
    access_level = session.get("access_level")
    # valid session check
    if not user_id:
        return render_template('error.html', error_message="Unauthorized access", error_code=403)
    # open DB connection
    conn = get_db_connection()
    cursor = conn.cursor()
    # Fetch passwords visible to user (own entries + those below access level)
    cursor.execute("""
        SELECT p.password_id, p.category_id, p.service_name, p.login_username, CAST(AES_DECRYPT(password_encrypted, %s) AS CHAR(255)) AS password_encrypted, p.notes, p.min_access_level, p.created_at, p.updated_at
        FROM passwords p
        WHERE p.min_access_level <= %s;
    """, (os.getenv("PSW_KEY"), session["access_level"]))
    rows = cursor.fetchall()
    cols = [desc[0] for desc in cursor.description]
    passwords = [dict(zip(cols, row)) for row in rows]
    cursor.close()
    conn.close()
    # render dashboard
    return render_template("dashboard.html", user_id=user_id, username=username, access_level=access_level, passwords=passwords)

@bp.route("/user_registration", methods=["GET", "POST"])
def user_registration():
    # get session info
    user_id = session.get("user_id")
    username = session.get("username")
    access_level = session.get("access_level")
    # valid session check
    if not user_id:
        return render_template('error.html', error_message="Unauthorized access", error_code=403)
    # render registration form on GET
    if request.method == "GET":
        return render_template("user_registration.html")
    # Check if user is super admin
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT access_level FROM users WHERE user_id=%s", (session["user_id"],))
    row = cursor.fetchone()
    # explicit check for null row
    if row is None:
        cursor.close()
        conn.close()
        return render_template('error.html', error_message="Unauthorized access", error_code=403)
    access_level = row[0]
    # explicit check for access level
    if access_level < 5:
        cursor.close()
        conn.close()
        return render_template('error.html', error_message="Unauthorized access", error_code=403)

    # process registration form on POST
    if request.method == "POST":
        new_username = request.form.get("username")
        new_password = request.form.get("password")
        access_level = request.form.get("access_level")
        # save password as hashed value
        hashed_pw = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        # create TOTP secret for new user
        totp_secret = pyotp.random_base32()
        # attempt user creation
        try:
            # create user in DB
            cursor.execute(
                "INSERT INTO users (username, password_hash, totp_secret, access_level) VALUES (%s, %s, %s, %s)",
                (new_username, hashed_pw, totp_secret, access_level)
            )
            conn.commit()
            # generate QR code for TOTP
            totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=new_username, issuer_name="Passman")
            img = qrcode.make(totp_uri)
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            img_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
            return render_template("show_qr.html", qr_code=img_str, secret=totp_secret, username=new_username)
        except Exception as e:
            # revert insert on error
            conn.rollback()
            return render_template('error.html', error_message=str(e), error_code=400)
        finally:
            # close connections
            cursor.close()
            conn.close()

    # close connection after GET checks are done
    cursor.close()
    conn.close()
    return render_template("user_registration.html")

@bp.route('/create_password', methods=["GET", "POST"])
def create_password():
    # get session info
    user_id = session.get("user_id")
    username = session.get("username")
    access_level = session.get("access_level")
    # valid session check
    if not user_id:
        return render_template('error.html', error_message="Unauthorized access", error_code=403)
    # check access level
    if access_level < 2:
        return render_template('error.html', error_message="Insufficient permissions", error_code=403)
    # render form on GET
    if request.method == 'GET':
        # DB open
        conn = get_db_connection()
        cursor = conn.cursor()
        # populate category dropdown
        cursor.execute("SELECT category_id, category_name FROM categories ORDER BY category_name")
        rows = cursor.fetchall()
        cols = [desc[0] for desc in cursor.description]
        categories = [dict(zip(cols, row)) for row in rows]
        # DB close
        cursor.close()
        conn.close()
        return render_template('create_password.html', categories=categories)
    # process form on POST
    if request.method == 'POST':
        # DB open
        conn = get_db_connection()
        cursor = conn.cursor()
        # pull form data
        service_name = request.form.get('service_name')
        login_username = request.form.get('login_username')
        password_plain = request.form.get('password_encrypted')
        password_confirmed = request.form.get('password_confirmed')
        notes = request.form.get('notes', None)
        category_id = request.form.get('category_id')
        min_access_level = request.form.get('min_access_level', 1)
        # validate passwords match
        if password_plain != password_confirmed:
            return render_template('error.html', error_message="Passwords do not match", error_code=400)
        # attempt insert
        try:
            cursor.execute("""
                INSERT INTO passwords 
                    (owner_user_id, category_id, service_name, login_username, password_encrypted, notes, min_access_level)
                VALUES (%s, %s, %s, %s, AES_ENCRYPT(%s, %s), %s, %s)
            """, (session['user_id'], category_id, service_name, login_username, password_plain, os.getenv("PSW_KEY"), notes, min_access_level))
            conn.commit()
        except Exception as e:
            conn.rollback()
            return render_template('error.html', error_message=str(e), error_code=400)
        finally:
            cursor.close()
            conn.close()
        # redirect to dashboard on success
        return redirect("/dashboard")

@bp.route('/update_password/', methods=['GET', 'POST'])
def update_password():
    # get session info
    user_id = session.get("user_id")
    username = session.get("username")
    access_level = session.get("access_level")
    # valid session check
    if not user_id:
        return render_template('error.html', error_message="Unauthorized access", error_code=403)
    # check access level
    if access_level < 3:
        return render_template('error.html', error_message="Insufficient permissions", error_code=403)
    # render form on GET
    if request.method == 'GET':
        password_id = request.args.get('password_id')
        # DB open
        conn = get_db_connection()
        cursor = conn.cursor()
        # fetch password details
        cursor.execute("""
            SELECT password_id, category_id, service_name, login_username, CAST(AES_DECRYPT(password_encrypted, %s) AS CHAR(255)) AS password_encrypted, notes, min_access_level
            FROM passwords
            WHERE password_id=%s
        """, (os.getenv("PSW_KEY"), password_id,))
        row = cursor.fetchone()
        cols = [desc[0] for desc in cursor.description]
        password_entry = dict(zip(cols, row))
        # DB close
        cursor.close()
        conn.close()
        return render_template('update_password.html', password=password_entry)
    # process form on POST
    if request.method == 'POST':
        # DB open
        conn = get_db_connection()
        cursor = conn.cursor()
        # pull form data
        password_id = request.form.get('password_id')
        password_encrypted = request.form.get('new_password')
        password_confirmed = request.form.get('confirm_password')
        # validate passwords match
        if password_encrypted != password_confirmed:
            return render_template('error.html', error_message="Passwords do not match", error_code=400)
        # attempt update
        try:
            cursor.execute("""
                UPDATE passwords
                SET password_encrypted=AES_ENCRYPT(%s, %s)
                WHERE password_id=%s
            """, (password_encrypted, os.getenv("PSW_KEY"), password_id))
            conn.commit()
        except Exception as e:
            conn.rollback()
            return render_template('error.html', error_message=str(e), error_code=400)
        finally:
            cursor.close()
            conn.close()
            # redirect to dashboard on success
            return redirect("/dashboard")

@bp.route('/delete_password/', methods=['GET', 'POST'])
def delete_password():
    # get session info
    user_id = session.get("user_id")
    username = session.get("username")
    access_level = session.get("access_level")
    # valid session check
    if not user_id:
        return render_template('error.html', error_message="Unauthorized access", error_code=403)
    # check access level
    if access_level < 4:
        return render_template('error.html', error_message="Insufficient permissions", error_code=403)
    # render confirmation on GET
    if request.method == 'GET':
        password_id = request.args.get('password_id')
        # DB open
        conn = get_db_connection()
        cursor = conn.cursor()
        # fetch password details
        cursor.execute("""
            SELECT service_name
            FROM passwords
            WHERE password_id=%s
        """, (password_id,))
        row = cursor.fetchone()
        if row is None:
            cursor.close()
            conn.close()
            return render_template('error.html', error_message="Password entry not found", error_code=404)
        account_name = row[0]
        # DB close
        cursor.close()
        conn.close()
        return render_template('confirm_delete.html', account_name=account_name, password_id=password_id)

    # process deletion on POST
    if request.method == 'POST':
        # DB open
        conn = get_db_connection()
        cursor = conn.cursor()
        # pull form data
        password_id = request.form.get('password_id')
        # attempt delete
        try:
            cursor.execute("""
                DELETE FROM passwords
                WHERE password_id=%s
            """, (password_id,))
            conn.commit()
        except Exception as e:
            conn.rollback()
            return render_template('error.html', error_message=str(e), error_code=400)
        finally:
            cursor.close()
            conn.close()
            # redirect to dashboard on success
            return redirect("/dashboard")

@bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/static/index.html')