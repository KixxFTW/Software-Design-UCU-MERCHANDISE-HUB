from flask import Flask, request, redirect, render_template, flash, session, jsonify, url_for, send_from_directory, get_flashed_messages
import mysql.connector
import bcrypt
import os
import requests

# Allow OAuth over HTTP for local development only.
# (OAuthlib otherwise requires HTTPS and raises (insecure_transport).)
if os.getenv("FLASK_ENV", "").lower() in {"development", "dev", "local"} or os.getenv("ENV", "").lower() in {"development", "dev", "local"}:
    os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")

from oauthlib.oauth2 import WebApplicationClient
import json
from werkzeug.utils import secure_filename
import uuid
import random
import smtplib
from email.mime.text import MIMEText

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'Admin'  # Required for session and flash messages

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Database configuration
DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': 'Admin',
    'database': 'usersdb'
}

# Google OAuth2 configuration
GOOGLE_CLIENT_ID = '718773630578-uk82823k8jr69moufe0fl5rrg4r9dalf.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# OAuth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Appwrite configuration (optional)
try:
    from appwrite.client import Client # type: ignore
    from appwrite.services.account import Account # type: ignore
    
    # Configure Appwrite connection
    appwrite_client = Client()
    appwrite_client.set_endpoint('https://cloud.appwrite.io/v1')
    appwrite_client.set_project('project-fra-6807d08800177b80f9c5')
    
    # Initialize Appwrite account
    appwrite_account = Account(appwrite_client)
    
    APPWRITE_ENABLED = True
    print("Appwrite integration enabled")
except ImportError:
    APPWRITE_ENABLED = False
    print("Appwrite SDK not found, continuing without Appwrite integration")

# Helper function to get Google provider configuration
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

# Email sending function
def send_email(to_email, subject, body):
    try:
        # Gmail SMTP settings
        sender_email = "valdezmarkjethro@gmail.com"  # Your Gmail address
        sender_password = "tmkd kzuh sqvc uvew"  # Your App Password
        
        # Create message
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = to_email

        # Connect to Gmail SMTP server
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
            print(f"Email sent successfully to {to_email}")
            return True
            
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

def _is_admin() -> bool:
    # Admin logic in this project is currently based on hardcoded student_id/course.
    return bool(session.get('student_id')) and (
        session.get('student_id') == 'ADMIN001' or session.get('course') == 'admin'
    )

def _merch_category_column(cursor) -> str:
    """
    Your project has mixed usage of `category` vs misspelled `catergory`.
    Detect which column exists in the running DB.
    """
    cursor.execute("SHOW COLUMNS FROM merchandise")
    cols = {row["Field"] if isinstance(row, dict) else row[0] for row in cursor.fetchall()}
    if "catergory" in cols:
        return "catergory"
    return "category"

def _to_public_image_url(raw_image: str | None) -> str:
    if not raw_image:
        return "/static/images/placeholder.png"
    image = str(raw_image).strip()
    if image.startswith("/static/") or image.startswith("http://") or image.startswith("https://"):
        return image
    return f"/static/images/{image}"

def _handle_instructor_google_oauth(user_info: dict):
    """
    Dedicated instructor Google OAuth handler:
    - validate email against educators table
    - update Google linkage
    - set instructor session
    """
    email = (user_info.get("email") or "").strip().lower()
    if not email:
        return False, "Google account has no email.", None

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM educators WHERE LOWER(email) = %s", (email,))
        instructor = cursor.fetchone()
        if not instructor:
            return False, "No instructor account found for this Google email. Please contact admin.", None

        cursor.execute(
            """
            UPDATE educators
            SET google_id = %s, google_email = %s
            WHERE id = %s
            """,
            (user_info.get("sub"), email, instructor.get("id")),
        )
        conn.commit()

        session['instructor_id'] = instructor.get('id')
        session['full_name'] = instructor.get('full_name')
        session['email'] = instructor.get('email')
        session['institution'] = instructor.get('institution')
        session['is_instructor'] = True
        return True, None, instructor
    except Exception as e:
        return False, str(e), None
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/merchandise', methods=['GET'])
def api_get_merchandise():
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        category_col = _merch_category_column(cursor)
        cursor.execute(
            f"""
            SELECT
                id,
                name,
                description,
                price,
                stock,
                image_url,
                {category_col} AS category
            FROM merchandise
            ORDER BY id DESC
            """
        )
        rows = cursor.fetchall()
        items = []
        for row in rows:
            items.append(
                {
                    "id": row.get("id"),
                    "name": row.get("name"),
                    "description": row.get("description") or "",
                    "price": float(row.get("price") or 0),
                    "stock": int(row.get("stock") or 0),
                    "image_url": _to_public_image_url(row.get("image_url")),
                    "category": (row.get("category") or "other"),
                }
            )
        return jsonify(items)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/products/<int:product_id>', methods=['GET'])
def api_get_product(product_id: int):
    """Used by AdminDashboard.html edit modal to prefill fields."""
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        category_col = _merch_category_column(cursor)
        cursor.execute(
            f"""
            SELECT
                id,
                name,
                description,
                price,
                stock,
                image_url,
                {category_col} AS category
            FROM merchandise
            WHERE id = %s
            """,
            (product_id,),
        )
        product = cursor.fetchone()
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        return jsonify(product)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/orders/<int:order_id>', methods=['GET'])
def api_get_order(order_id: int):
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                o.id,
                o.student_id,
                o.total_amount,
                o.status,
                o.payment_status,
                o.payment_method,
                o.delivery_option,
                o.delivery_address,
                o.created_at,
                s.first_name,
                s.last_name,
                s.email
            FROM orders o
            LEFT JOIN students s ON s.student_id = o.student_id
            WHERE o.id = %s
            """,
            (order_id,),
        )
        order = cursor.fetchone()
        if not order:
            return jsonify({'error': 'Order not found'}), 404

        cursor.execute(
            """
            SELECT
                oi.quantity,
                oi.price,
                m.name AS product_name
            FROM order_items oi
            LEFT JOIN merchandise m ON m.id = oi.item_id
            WHERE oi.order_id = %s
            """,
            (order_id,),
        )
        order["items"] = cursor.fetchall()
        return jsonify(order)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/orders/<int:order_id>/status', methods=['POST'])
def api_update_order_status(order_id: int):
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json(silent=True) or {}
    new_status = (data.get('status') or '').strip().lower()
    reference_number = (data.get('reference_number') or '').strip()
    allowed = {'pending': 'Pending', 'completed': 'Completed', 'cancelled': 'Cancelled'}
    if new_status not in allowed:
        return jsonify({'error': 'Invalid order status'}), 400

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("UPDATE orders SET status=%s WHERE id=%s", (allowed[new_status], order_id))

        # When order is completed, insert into payments table
        if new_status == 'completed':
            cursor.execute(
                """
                SELECT o.total_amount, o.payment_method, s.email AS student_email, e.email AS instructor_email
                FROM orders o
                LEFT JOIN students s ON s.student_id = o.student_id
                LEFT JOIN educators e ON e.id = o.instructor_id
                WHERE o.id = %s
                """,
                (order_id,),
            )
            order = cursor.fetchone()
            if order:
                email = order.get('student_email') or order.get('instructor_email') or 'unknown'
                amount = order.get('total_amount') or 0
                payment_method = order.get('payment_method') or 'Unknown'
                ref = reference_number if reference_number else f"ORD-{order_id}"
                cursor.execute(
                    """
                    INSERT INTO payments (email, amount, payment_method, reference_number, status, payment_date)
                    VALUES (%s, %s, %s, %s, 'Success', NOW())
                    ON DUPLICATE KEY UPDATE status='Success', payment_date=NOW(), reference_number=%s
                    """,
                    (email, amount, payment_method, ref, ref),
                )

        conn.commit()
        return jsonify({'success': True, 'status': new_status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/orders/<int:order_id>/payment-status', methods=['POST'])
def api_update_order_payment_status(order_id: int):
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json(silent=True) or {}
    new_status = (data.get('payment_status') or '').strip()
    allowed = {'Pending', 'Success', 'Failed', 'Refund Requested', 'Refunded'}
    if new_status not in allowed:
        return jsonify({'error': 'Invalid payment status'}), 400

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("UPDATE orders SET payment_status=%s WHERE id=%s", (new_status, order_id))

        # If marking as Success, insert into payments table
        if new_status == 'Success':
            cursor.execute(
                """
                SELECT o.total_amount, o.payment_method, s.email AS student_email, e.email AS instructor_email
                FROM orders o
                LEFT JOIN students s ON s.student_id = o.student_id
                LEFT JOIN educators e ON e.id = o.instructor_id
                WHERE o.id = %s
                """,
                (order_id,),
            )
            order = cursor.fetchone()
            if order:
                email = order.get('student_email') or order.get('instructor_email') or 'unknown'
                amount = order.get('total_amount') or 0
                payment_method = order.get('payment_method') or 'Unknown'
                ref = f"ORD-{order_id}"
                cursor.execute(
                    """
                    INSERT INTO payments (email, amount, payment_method, reference_number, status, payment_date)
                    VALUES (%s, %s, %s, %s, 'Success', NOW())
                    ON DUPLICATE KEY UPDATE status='Success', payment_date=NOW()
                    """,
                    (email, amount, payment_method, ref),
                )

        # If marking as Refunded, remove from payments table
        if new_status == 'Refunded':
            cursor.execute(
                "DELETE FROM payments WHERE reference_number = %s",
                (f"ORD-{order_id}",),
            )

        conn.commit()
        return jsonify({'success': True, 'payment_status': new_status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/orders/<int:order_id>/process', methods=['POST'])
def api_process_order(order_id: int):
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("UPDATE orders SET status='Pending' WHERE id=%s", (order_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/orders/<int:order_id>/complete', methods=['POST'])
def api_complete_order(order_id: int):
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("UPDATE orders SET status='Completed' WHERE id=%s", (order_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/orders/<int:order_id>/cancel', methods=['POST'])
def api_cancel_order(order_id: int):
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("UPDATE orders SET status='Cancelled' WHERE id=%s", (order_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/payments/<int:payment_id>', methods=['GET'])
def api_get_payment(payment_id: int):
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                p.id,
                p.email,
                p.amount,
                p.payment_method,
                p.reference_number,
                p.status,
                p.payment_date,
                COALESCE(e.full_name, p.email) AS instructor_name
            FROM payments p
            LEFT JOIN educators e ON e.email = p.email
            WHERE p.id = %s
            """,
            (payment_id,),
        )
        payment = cursor.fetchone()
        if not payment:
            return jsonify({'error': 'Payment not found'}), 404
        payment["amount"] = float(payment.get("amount") or 0)
        return jsonify(payment)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/payments/<int:payment_id>/status', methods=['POST'])
def api_update_payment_status(payment_id: int):
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json(silent=True) or {}
    new_status = (data.get('status') or '').strip()
    allowed = {'Pending', 'Success', 'Failed', 'Refund Requested', 'Refunded'}
    if new_status not in allowed:
        return jsonify({'error': 'Invalid payment status'}), 400

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("UPDATE payments SET status=%s WHERE id=%s", (new_status, payment_id))
        conn.commit()
        return jsonify({'success': True, 'status': new_status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/payments/<int:payment_id>/confirm', methods=['POST'])
def api_confirm_payment(payment_id: int):
    if not _is_admin():
        return jsonify({'error': 'Access denied'}), 403
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("UPDATE payments SET status='Success' WHERE id=%s", (payment_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# ROUTE FOR THE LOGIN PAGE
@app.route('/')
def index():
    # Retrieve flash messages
    messages = get_flashed_messages(with_categories=True)
    return render_template('Index.html', messages=messages)

#SIGNUP ROUTE
@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('SignupAS.html')

# ROUTE TO HANDLE SIGNUP LOGIC
@app.route('/signup', methods=['POST'])
def process_signup():
    try:
        # Get form data
        student_id = request.form.get('student_id')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Connect to database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Insert new user
        query = "INSERT INTO students (student_id, first_name, last_name, email, password, course) VALUES (%s, %s, %s, %s, %s, %s)"
        cursor.execute(query, (student_id, first_name, last_name, email, hashed_password, 'N/A'))
        conn.commit()
        
        # After successful signup, before redirecting to login/dashboard:
        generate_and_send_otp(student_id, email)
        return redirect(f'/verify_otp/{student_id}')
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect('/signup')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/signup')
    finally:
        if 'cursor' in locals():
            cursor.fetchall()  # Clear any unread results
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Route to handle signup for students with expanded fields
@app.route('/signup/student', methods=['POST'])
def signup_student():
    try:
        # Retrieve form data
        student_id = request.form.get('student-school')
        first_name = request.form.get('student-name')
        last_name = request.form.get('student-last-name')
        email = request.form.get('student-email')
        password = request.form.get('student-password')
        confirm_password = request.form.get('student-confirm-password')
        course = request.form.get('student-course')

        # Validate form data
        if not student_id or not first_name or not last_name or not email or not password or not confirm_password or not course:
            flash('All fields are required.', 'danger')
            return redirect('/signup')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect('/signup')

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Insert into the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        query = """
            INSERT INTO students (student_id, first_name, last_name, email, password, course)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (student_id, first_name, last_name, email, hashed_password, course))
        conn.commit()

        # Add a flash message with a success flag
        flash('Student account created successfully! You can now log in.', 'success')
        session['signup_success'] = True  # Add a session flag for success
        return redirect('/')
    except Exception as e:
        flash(f'An error occurred during student signup: {e}', 'danger')
        return redirect('/signup')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Route to handle signup for educators
@app.route('/signup/educator', methods=['POST'])
def signup_educator():
    conn = None
    cursor = None
    try:
        # Get form data
        full_name = request.form.get('educator-name')
        email = request.form.get('educator-email')
        password = request.form.get('educator-password')
        institution = request.form.get('educator-institution')
        subject = request.form.get('educator-subject')

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Insert educator data into the database
        query = """
            INSERT INTO educators (full_name, email, password, institution, subject)
            VALUES (%s, %s, %s, %s, %s)
        """
        values = (full_name, email, hashed_password, institution, subject)
        cursor.execute(query, values)
        conn.commit()

        flash('Instructor account created successfully! You can now log in.', 'success')
        return redirect('/')
    except Exception as e:
        flash(f'An error occurred during instructor signup: {e}', 'danger')
        return redirect('/signup')
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# Route to handle login
@app.route('/login', methods=['POST'])
def login():
    try:
        # Get form data
        student_id = request.form.get('student_id')
        password = request.form.get('password')

        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Query the database for the student_id
        query = "SELECT * FROM students WHERE student_id = %s"
        cursor.execute(query, (student_id,))
        user = cursor.fetchone()  # Fetch the result

        # Check if user exists and verify the password
        if user:
            # Convert both password and stored hash to bytes if they aren't already
            password_bytes = password.encode('utf-8')
            stored_hash = user['password'].encode('utf-8') if isinstance(user['password'], str) else bytes(user['password'])
            
            if bcrypt.checkpw(password_bytes, stored_hash):
                # Set session data
                session['student_id'] = user['student_id']
                session['first_name'] = user['first_name']
                session['last_name'] = user['last_name']
                session['email'] = user['email']
                session['role'] = user.get('role', 'student')  # Store user role in session
                # Needed for admin checks in other routes (e.g. `/admin/dashboard`)
                session['course'] = user.get('course')
                
                # Clear any unread results
                cursor.fetchall()
                
                # Check if user is admin
                if user['student_id'] == 'ADMIN001' or user.get('course') == 'admin':
                    flash(f'Welcome back, {user["first_name"]}!', 'success')
                    return redirect('/admin/dashboard')
                
                # For regular students
                flash(f'Welcome back, {user["first_name"]}!', 'success')
                return redirect('/dashboard')
            else:
                flash('Password does not match. Please try again.', 'danger')
                return redirect('/')
        else:
            flash('Invalid Student ID or Password. Please try again.', 'danger')
            return redirect('/')
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect('/')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/')
    finally:
        if 'cursor' in locals():
            cursor.close()  # Ensure the cursor is closed
        if 'conn' in locals():
            conn.close()  # Ensure the connection is closed

# Route to initiate Google login
@app.route('/login/google')
def google_login():
    # Get Google configuration
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    
    # Use the client to generate a request URI
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for('google_callback', _external=True),
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

# Add a new route for instructor Google login
@app.route('/login/google/instructor')
def google_login_instructor():
    # Get Google configuration
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    
    # Store instructor intent in session so the shared callback can route correctly
    session['oauth_target'] = 'instructor'
    
    # Use the SAME redirect_uri as the student flow (must match Google Console config)
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for('google_callback', _external=True),
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

# Route to handle Google callback
@app.route('/login/google/callback')
def google_callback():
    try:
        # Get authorization code from Google
        code = request.args.get("code")
        
        # Get token endpoint from Google configuration
        google_provider_cfg = get_google_provider_cfg()
        token_endpoint = google_provider_cfg["token_endpoint"]
        
        # Prepare the token request
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=url_for('google_callback', _external=True),
            code=code
        )
        
        # Send the request to get tokens
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        )
        
        # Parse the token response
        client.parse_request_body_response(json.dumps(token_response.json()))
        
        # Get user info from Google
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body)
        
        if userinfo_response.json().get("email_verified"):
            user_info = userinfo_response.json()
            
            # Route based on session flag set in /login/google/instructor
            if session.pop('oauth_target', None) == 'instructor':
                ok, error_message, instructor = _handle_instructor_google_oauth(user_info)
                if not ok:
                    flash(error_message or 'Instructor Google login failed.', 'danger')
                    return redirect('/')
                flash(f"Welcome {instructor.get('full_name', 'Instructor')}! You have successfully logged in as an instructor.", 'success')
                return redirect('/instructor/dashboard')
            
            # Otherwise, handle as student flow
            email = user_info["email"]
            first_name = user_info.get("given_name", "")
            last_name = user_info.get("family_name", "")
            google_id = user_info["sub"]
            
            # Check if user exists in database
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor(dictionary=True)
            query = "SELECT * FROM students WHERE email = %s"
            cursor.execute(query, (email,))
            user = cursor.fetchone()
            
            if not user:
                # Generate a random password for the user
                random_password = os.urandom(16).hex()
                hashed_password = bcrypt.hashpw(random_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                # Store Google account information
                query = """
                    INSERT INTO students (student_id, first_name, last_name, email, password, course, google_id, google_email, google_password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(query, (
                    google_id, 
                    first_name, 
                    last_name, 
                    email, 
                    hashed_password,
                    'N/A',
                    google_id,
                    email,
                    hashed_password  # Store the hashed password for Google account
                ))
                conn.commit()
                
                # Get the newly created user
                query = "SELECT * FROM students WHERE email = %s"
                cursor.execute(query, (email,))
                user = cursor.fetchone()
            session['student_id'] = user['student_id']
            session['first_name'] = user['first_name']
            session['last_name'] = user['last_name']
            session['email'] = user['email']
            
            cursor.fetchall()  # Clear any unread results
            cursor.close()
            conn.close()
            
            return redirect('/dashboard')
        else:
            flash('Google authentication failed. Email not verified.', 'danger')
            return redirect('/')
    except Exception as e:
        flash(f"An error occurred during Google login: {e}", 'danger')
        return redirect('/')

# Route to handle Google callback for instructors
@app.route('/login/google/instructor/callback')
def google_instructor_callback():
    try:
        # Get authorization code from Google
        code = request.args.get("code")
        
        # Get token endpoint from Google configuration
        google_provider_cfg = get_google_provider_cfg()
        token_endpoint = google_provider_cfg["token_endpoint"]
        
        # Prepare the token request
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=url_for('google_instructor_callback', _external=True),
            code=code
        )
        
        # Send the request to get tokens
        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        )
        
        # Parse the token response
        client.parse_request_body_response(json.dumps(token_response.json()))
        
        # Get user info from Google
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body)
        
        if userinfo_response.json().get("email_verified"):
            user_info = userinfo_response.json()
            ok, error_message, instructor = _handle_instructor_google_oauth(user_info)
            if not ok:
                flash(error_message or 'Instructor Google login failed.', 'danger')
                return redirect('/')
            
            flash(f"Welcome {instructor.get('full_name', 'Instructor')}! You have successfully logged in as an instructor.", 'success')
            return redirect('/instructor/dashboard')
        else:
            flash('Google authentication failed. Email not verified.', 'danger')
            return redirect('/')
    except Exception as e:
        flash(f"An error occurred during Google login: {e}", 'danger')
        return redirect('/')

# Google OAuth callback for AJAX/API requests
@app.route('/auth/google/callback', methods=['POST'])
def google_api_callback():
    token = request.json.get('token')
    if not token:
        return jsonify({'error': 'No token provided'}), 400
    
    # Verify token with Google
    response = requests.get(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        headers={'Authorization': f'Bearer {token}'}
    )
    
    if response.status_code != 200:
        return jsonify({'error': 'Invalid token'}), 401
    
    user_info = response.json()
    
    # Check if user exists in database
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    query = "SELECT * FROM students WHERE email = %s"
    cursor.execute(query, (user_info.get('email'),))
    user = cursor.fetchone()

    if not user:
        # Create new user if doesn't exist - using empty string password instead of bytes
        empty_password_hash = bcrypt.hashpw("".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        query = "INSERT INTO students (student_id, first_name, last_name, email, password, course) VALUES (%s, %s, %s, %s, %s, %s)"
        cursor.execute(query, (
            user_info.get('sub'),  # Use Google user ID as student_id
            user_info.get('given_name'),
            user_info.get('family_name'),
            user_info.get('email'),
            empty_password_hash,
            'N/A'
        ))
        conn.commit()
        user = {
            'student_id': user_info.get('sub'),
            'first_name': user_info.get('given_name'),
            'last_name': user_info.get('family_name'),
            'email': user_info.get('email')
        }
        
        print(f"New user created via Google API: {user['email']} (ID: {user['student_id']})")
    else:
        print(f"User logged in via Google API: {user['email']}")
    
    # Store user info in session
    session['student_id'] = user['student_id']
    session['first_name'] = user['first_name']
    session['last_name'] = user['last_name']
    session['email'] = user['email']
    
    cursor.fetchall()  # Clear any unread results
    cursor.close()
    conn.close()
    
    return jsonify({
        'success': True, 
        'message': f"Welcome {user['first_name']}! You are now logged in.",
        'user': {
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'email': user['email']
        }
    })

# dASHBOARD ROUTE
@app.route('/dashboard')
def dashboard():
    if 'student_id' in session:
        # Calculate user initials (from Django views.py)
        full_name = f"{session.get('first_name', '')} {session.get('last_name', '')}"
        initials = ''.join([name[0] for name in full_name.split() if name])
        
        return render_template(
            'Dashboard.html',
            first_name=session.get('first_name'),
            last_name=session.get('last_name'),
            student_id=session.get('student_id'),
            user_initials=initials,
            user_name=full_name
        )
    else:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect('/')

# Add a route for instructor dashboard
@app.route('/instructor/dashboard')
def instructor_dashboard():
    if 'instructor_id' in session and session.get('is_instructor'):
        # Calculate user initials
        full_name = session.get('full_name', '')
        initials = ''.join([name[0] for name in full_name.split() if name])

        conn = None
        cursor = None
        merchandise = []
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor(dictionary=True)
            category_col = _merch_category_column(cursor)
            cursor.execute(
                f"""
                SELECT id, name, description, price, stock, image_url, {category_col} AS category
                FROM merchandise
                ORDER BY id DESC
                """
            )
            merchandise = cursor.fetchall()
            for item in merchandise:
                img = item.get('image_url') or ''
                if img and not img.startswith('/'):
                    item['image_url'] = f'/static/images/{img}'
        except Exception as e:
            print(f"[instructor_dashboard ERROR] {e}")
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

        return render_template(
            'InstructorDashboard.html',
            full_name=session.get('full_name'),
            email=session.get('email'),
            institution=session.get('institution'),
            user_initials=initials,
            user_name=full_name,
            merchandise=merchandise
        )
    else:
        flash('Please log in as an instructor to access the dashboard.', 'danger')
        return redirect('/')

# Route to handle logout
@app.route('/logout')
def logout():
    # Clear session
    session.clear()
    flash('You have been successfully logged out.', 'success')
    return redirect('/')

# Add a success page route
@app.route('/success')
def success():
    message = request.args.get('message', 'Operation completed successfully!')
    return render_template('success.html', message=message)


#PAYMENT HTML ROUTE
@app.route('/payment')
def payment():
    return render_template('Payment.html')

@app.route('/Settings')
def settings_redirect():
    return redirect('/settings')

#SETTINGS ROUTE
@app.route('/settings')
def settings():
    print("Session contents:", session)  # Debugging
    if 'student_id' not in session:
        flash('Please log in to access your settings.', 'danger')
        return redirect('/')

    try:
        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Fetch user information
        query = "SELECT * FROM students WHERE student_id = %s"
        cursor.execute(query, (session.get('student_id'),))
        user = cursor.fetchone()

        if not user:
            flash('User not found.', 'danger')
            return redirect('/dashboard')

        # Fetch notification preferences
        notification_query = "SELECT * FROM notification_preferences WHERE student_id = %s"
        cursor.execute(notification_query, (session.get('student_id'),))
        notifications = cursor.fetchone()

        # Default notification preferences if not set
        if not notifications:
            notifications = {'email': True, 'sms': False}

        # Calculate user initials for avatar
        first_name = user.get('first_name', '')
        last_name = user.get('last_name', '')
        user_initials = (first_name[0] if first_name else '') + (last_name[0] if last_name else '')

        # Render the settings page
        return render_template(
            'Settings.html',
            user=user,
            user_initials=user_initials,
            first_name=first_name,
            last_name=last_name,
            student_id=user.get('student_id'),
            notification_preferences=notifications,
            message=request.args.get('message'),
            message_type=request.args.get('message_type', 'info')
        )
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect('/settings')  # Use lowercase
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/Settings')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals() and conn.is_connected():
            conn.close()


#UPDATE PROFILE ROUTE
@app.route('/update_profile', methods=['POST'])
def update_profile():
    try:
        # Get form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')

        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Update user information
        if password:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            query = """
                UPDATE students
                SET first_name = %s, last_name = %s, email = %s, password = %s
                WHERE student_id = %s
            """
            cursor.execute(query, (first_name, last_name, email, hashed_password, session.get('student_id')))
            
            # Show success message with password change
            user_name = session.get('first_name', 'User')
            flash(f'🎉 Congratulations {user_name}! Your profile and password have been successfully updated. Please use your new password for your next login.', 'success')
        else:
            query = """
                UPDATE students
                SET first_name = %s, last_name = %s, email = %s
                WHERE student_id = %s
            """
            cursor.execute(query, (first_name, last_name, email, session.get('student_id')))
            
            # Show success message for profile update only
            user_name = session.get('first_name', 'User')
            flash(f'Profile updated successfully, {user_name}!', 'success')

        conn.commit()

        # Update session data with new values
        session['first_name'] = first_name
        session['last_name'] = last_name
        session['email'] = email

        return redirect('/settings')
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect('/settings')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/settings')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


#UPDATE PASSWORD ROUTE
@app.route('/update_password', methods=['POST'])
def update_password():
    try:
        # Get form data
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validate input
        if not current_password or not new_password or not confirm_password:
            flash('Please fill in all password fields.', 'danger')
            return redirect('/settings')

        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect('/settings')

        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Get user's current password
        if 'is_instructor' in session and session['is_instructor']:
            query = "SELECT password FROM educators WHERE id = %s"
            user_id = session['instructor_id']
        else:
            query = "SELECT password FROM students WHERE student_id = %s"
            user_id = session['student_id']

        cursor.execute(query, (user_id,))
        user = cursor.fetchone()

        if not user:
            flash('User not found.', 'danger')
            return redirect('/settings')

        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password'].encode('utf-8')):
            flash('Current password is incorrect.', 'danger')
            return redirect('/settings')

        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Update password in database
        if 'is_instructor' in session and session['is_instructor']:
            update_query = "UPDATE educators SET password = %s WHERE id = %s"
        else:
            update_query = "UPDATE students SET password = %s WHERE student_id = %s"

        cursor.execute(update_query, (hashed_password, user_id))
        conn.commit()

        # Show success message with user's name
        user_name = session.get('full_name', 'User')
        flash(f'🎉 Congratulations {user_name}! Your password has been successfully changed. Please use your new password for your next login.', 'success')
        return redirect('/settings')
        return redirect('/settings')

    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect('/settings')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/settings')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals() and conn.is_connected():
            conn.close()

#Instructor App route
@app.route('/login/instructor', methods=['POST'])
def instructor_login():
    try:
        # Get form data
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please provide both email and password.', 'danger')
            return redirect('/')

        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Fetch instructor by email
        query = "SELECT * FROM educators WHERE email = %s"
        cursor.execute(query, (email,))
        instructor = cursor.fetchone()

        if not instructor:
            flash('No instructor found with this email.', 'danger')
            return redirect('/')

        # Check password
        try:
            # Convert password to bytes
            password_bytes = password.encode('utf-8')
            # Convert stored hash to bytes, handling both string and bytearray cases
            stored_hash = instructor['password']
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode('utf-8')
            elif isinstance(stored_hash, bytearray):
                stored_hash = bytes(stored_hash)
            
            if bcrypt.checkpw(password_bytes, stored_hash):
                # Store instructor info in session
                session.clear()  # Clear any existing session
                session['instructor_id'] = instructor['id']
                session['full_name'] = instructor['full_name']
                session['email'] = instructor['email']
                session['institution'] = instructor['institution']
                session['is_instructor'] = True

                flash(f"Welcome back, {instructor['full_name']}!", 'success')
                return redirect('/instructor/dashboard')
            else:
                flash('Invalid password.', 'danger')
                return redirect('/')
        except Exception as e:
            print(f"Password verification error: {str(e)}")  # Log the actual error
            flash('Error verifying password. Please try again.', 'danger')
            return redirect('/')

    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect('/')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals() and conn.is_connected():
            conn.close()

@app.route('/update_notifications', methods=['POST'])
def update_notifications():
    try:
        # Get form data
        email_notifications = request.form.get('email_notifications') == 'on'
        sms_notifications = request.form.get('sms_notifications') == 'on'

        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Check if notification preferences exist
        check_query = "SELECT * FROM notification_preferences WHERE student_id = %s"
        cursor.execute(check_query, (session.get('student_id'),))
        exists = cursor.fetchone()

        if exists:
            # Update existing preferences
            query = """
                UPDATE notification_preferences
                SET email = %s, sms = %s
                WHERE student_id = %s
            """
            cursor.execute(query, (email_notifications, sms_notifications, session.get('student_id')))
        else:
            # Insert new preferences
            query = """
                INSERT INTO notification_preferences (student_id, email, sms)
                VALUES (%s, %s, %s)
            """
            cursor.execute(query, (session.get('student_id'), email_notifications, sms_notifications))

        conn.commit()
        flash('Notification preferences updated successfully!', 'success')
        return redirect('/settings')
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect('/settings')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/settings')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/deactivate_account', methods=['POST'])
def deactivate_account():
    try:
        # Get form data
        password = request.form.get('password')
        reason = request.form.get('reason', '')

        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Verify password
        query = "SELECT password FROM students WHERE student_id = %s"
        cursor.execute(query, (session.get('student_id'),))
        user = cursor.fetchone()

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            flash('Invalid password.', 'danger')
            return redirect('/settings')

        # Update account status
        query = """
            UPDATE students
            SET is_active = FALSE, deactivation_reason = %s
            WHERE student_id = %s
        """
        cursor.execute(query, (reason, session.get('student_id')))
        conn.commit()

        # Clear session and logout
        session.clear()
        flash('Your account has been deactivated. Contact the administrator to reactivate it.', 'success')
        return redirect('/')
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect('/settings')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/settings')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/delete_account', methods=['POST'])
def delete_account():
    try:
        # Get form data
        password = request.form.get('password')
        confirm_delete = request.form.get('confirm_delete')

        if not confirm_delete:
            flash('Please confirm account deletion.', 'danger')
            return redirect('/settings')

        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Verify password
        query = "SELECT password FROM students WHERE student_id = %s"
        cursor.execute(query, (session.get('student_id'),))
        user = cursor.fetchone()

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            flash('Invalid password.', 'danger')
            return redirect('/settings')

        # Delete all related data in the correct order to maintain referential integrity
        queries = [
            "DELETE FROM notification_preferences WHERE student_id = %s",
            "DELETE FROM enrolled_courses WHERE student_id = %s",
            "DELETE FROM grades WHERE student_id = %s",
            "DELETE FROM payment_history WHERE student_id = %s",
            "DELETE FROM students WHERE student_id = %s"
        ]

        for query in queries:
            try:
                cursor.execute(query, (session.get('student_id'),))
            except mysql.connector.Error as err:
                # Log the error but continue with deletion
                print(f"Error executing query {query}: {err}")
                continue
        
        conn.commit()

        # Clear session and logout
        session.clear()
        flash('Your account and all associated data have been permanently deleted.', 'success')
        return redirect('/')
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect('/settings')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/settings')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/instructor_settings', methods=['GET', 'POST'])
def instructor_settings():
    if 'instructor_id' not in session:
        return redirect(url_for('instructor_login'))
    
    if request.method == 'POST':
        if 'change_password' in request.form:
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            
            # Connect to database
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor(dictionary=True)
            
            try:
                # Verify current password
                cursor.execute("SELECT password FROM educators WHERE id = %s", (session['instructor_id'],))
                instructor = cursor.fetchone()
                
                if not instructor:
                    flash('Instructor not found.', 'danger')
                    return redirect(url_for('instructor_settings'))
                
                # Convert stored hash to bytes if it's a bytearray
                stored_hash = instructor['password']
                if isinstance(stored_hash, bytearray):
                    stored_hash = bytes(stored_hash)

                # Verify current password
                if not bcrypt.checkpw(current_password.encode('utf-8'), stored_hash):
                    flash('Current password is incorrect.', 'danger')
                    return redirect(url_for('instructor_settings'))
                
                if new_password != confirm_password:
                    flash('New passwords do not match.', 'danger')
                    return redirect(url_for('instructor_settings'))
                
                # Update password
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("UPDATE educators SET password = %s WHERE id = %s", 
                            (hashed_password, session['instructor_id']))
                conn.commit()
                
                flash('Password successfully changed!', 'success')
                return redirect(url_for('instructor_settings'))
                
            except Exception as e:
                flash('An error occurred while changing the password.', 'danger')
                print(f"Error: {str(e)}")
            finally:
                cursor.close()
                conn.close()
    
    return render_template('InstructorSettings.html')

@app.route('/instructor_payment', methods=['GET', 'POST'])
def instructor_payment():
    try:
        # Check if instructor is logged in using email
        if 'email' not in session:
            flash('Please log in to view payment details.', 'warning')
            return redirect('/')

        instructor_email = session.get('email')
        
        # Connect to database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        if request.method == 'POST':
            # Handle payment processing
            amount = request.form.get('amount')
            payment_method = request.form.get('payment_method')
            reference_number = request.form.get('reference_number')
            
            if not all([amount, payment_method, reference_number]):
                flash('Please fill in all payment details', 'error')
                return redirect(url_for('instructor_payment'))
            
            # Insert payment record
            cursor.execute("""
                INSERT INTO payments (email, amount, payment_method, reference_number, status, payment_date)
                VALUES (%s, %s, %s, %s, 'Pending', NOW())
            """, (instructor_email, amount, payment_method, reference_number))
            
            conn.commit()
            flash('Payment submitted successfully! Please wait for confirmation.', 'success')
            return redirect(url_for('instructor_payment'))

        # Get payment history for GET requests
        query = """
            SELECT p.id, p.amount, p.payment_method, p.reference_number, 
                   p.status, p.payment_date
            FROM payments p
            WHERE p.email = %s
            ORDER BY p.payment_date DESC, p.id DESC
        """
        cursor.execute(query, (instructor_email,))
        payments = cursor.fetchall()

        cursor.close()
        conn.close()

        # Get instructor's full name from session
        full_name = session.get('full_name', 'Instructor')
        user_initials = ''.join([name[0].upper() for name in full_name.split() if name])

        return render_template('InstructorPayment.html', 
                            payments=payments,
                            full_name=full_name,
                            email=instructor_email,
                            user_initials=user_initials)
                             
    except Exception as e:
        print(f"Database error: {str(e)}")
        flash(f"An error occurred while fetching payment details: {e}", 'danger')
        return redirect(url_for('instructor_dashboard'))

# Cart Management Routes
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    # Check if user is logged in (either student or instructor)
    user_id = session.get('student_id') or session.get('instructor_id')
    user_type = 'student_id' if 'student_id' in session else 'instructor_id'
    
    if not user_id:
        return jsonify({'error': 'Please log in to add items to cart'}), 401
    
    try:
        data = request.get_json()
        item_identifier = data.get('item_id')  # Could be ID or name
        quantity = data.get('quantity', 1)
        size = data.get('size')
        
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Try to get item by ID first, then by name if ID fails
        cursor.execute("SELECT * FROM merchandise WHERE id = %s", (item_identifier,))
        item = cursor.fetchone()
        
        if not item:
            # If not found by ID, try by name
            cursor.execute("SELECT * FROM merchandise WHERE name = %s", (item_identifier,))
            item = cursor.fetchone()
        
        if not item:
            return jsonify({'error': f'Item not found: {item_identifier}'}), 404
        
        # Add to cart in database using the resolved merchandise row ID
        item_db_id = item['id']
        if user_type == 'student_id':
            cursor.execute("""
                INSERT INTO cart_items (student_id, item_id, quantity)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE quantity = quantity + %s
            """, (user_id, item_db_id, quantity, quantity))
        else:
            cursor.execute("""
                INSERT INTO cart_items (instructor_id, item_id, quantity)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE quantity = quantity + %s
            """, (user_id, item_db_id, quantity, quantity))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Item added to cart successfully',
            'item': {
                'id': item['id'],
                'name': item['name'],
                'price': item['price'],
                'quantity': quantity
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    # Check if user is logged in (either student or instructor)
    user_id = session.get('student_id') or session.get('instructor_id')
    user_type = 'student_id' if 'student_id' in session else 'instructor_id'
    
    if not user_id:
        return jsonify({'error': 'Please log in to modify cart'}), 401
    
    try:
        data = request.get_json()
        item_id = data.get('item_id')
        
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Delete from cart using appropriate column
        if user_type == 'student_id':
            cursor.execute("""
                DELETE FROM cart_items 
                WHERE student_id = %s AND item_id = %s
            """, (user_id, item_id))
        else:
            cursor.execute("""
                DELETE FROM cart_items 
                WHERE instructor_id = %s AND item_id = %s
            """, (user_id, item_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Item removed from cart successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/update_cart_quantity', methods=['POST'])
def update_cart_quantity():
    # Check if user is logged in (either student or instructor)
    user_id = session.get('student_id') or session.get('instructor_id')
    user_type = 'student_id' if 'student_id' in session else 'instructor_id'
    
    if not user_id:
        return jsonify({'error': 'Please log in to modify cart'}), 401
    
    try:
        data = request.get_json()
        item_id = data.get('item_id')
        quantity = data.get('quantity')
        
        if quantity < 1:
            return jsonify({'error': 'Quantity must be at least 1'}), 400
        
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Update cart using appropriate column
        if user_type == 'student_id':
            cursor.execute("""
                UPDATE cart_items 
                SET quantity = %s 
                WHERE student_id = %s AND item_id = %s
            """, (quantity, user_id, item_id))
        else:
            cursor.execute("""
                UPDATE cart_items 
                SET quantity = %s 
                WHERE instructor_id = %s AND item_id = %s
            """, (quantity, user_id, item_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Cart quantity updated successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_cart', methods=['GET'])
def get_cart():
    # Check if user is logged in (either student or instructor)
    user_id = session.get('student_id') or session.get('instructor_id')
    user_type = 'student_id' if 'student_id' in session else 'instructor_id'
    
    if not user_id:
        return jsonify({'error': 'Please log in to view cart'}), 401
    
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Use appropriate column name based on user type
        if user_type == 'student_id':
            cursor.execute("""
                SELECT ci.*, m.name, m.price, m.image_url
                FROM cart_items ci
                JOIN merchandise m ON ci.item_id = m.id
                WHERE ci.student_id = %s
            """, (user_id,))
        else:
            cursor.execute("""
                SELECT ci.*, m.name, m.price, m.image_url
                FROM cart_items ci
                JOIN merchandise m ON ci.item_id = m.id
                WHERE ci.instructor_id = %s
            """, (user_id,))
        
        cart_items = cursor.fetchall()
        cursor.close()
        conn.close()

        # Normalize image URLs to full static paths
        for item in cart_items:
            img = item.get('image_url') or ''
            if img and not img.startswith('/'):
                item['image_url'] = f'/static/images/{img}'
        
        return jsonify({
            'success': True,
            'cart_items': cart_items
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Order Processing Routes
@app.route('/process_order', methods=['POST'])
def process_order():
    try:
        # Allow both student and instructor sessions to place an order.
        buyer_id = session.get('student_id') or session.get('instructor_id')
        if not buyer_id:
            return jsonify({'error': 'Please log in to process order'}), 401

        data = request.get_json()
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid JSON payload'}), 400

        payment_method = data.get('payment_method')
        delivery_option = data.get('delivery_option')
        delivery_address = data.get('delivery_address')
        cart_items = data.get('cart_items') or []
        
        if not all([payment_method, delivery_option, delivery_address]):
            return jsonify({'error': 'Missing required order information'}), 400

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # If frontend didn't send cart_items, load from database cart for this user
        if not isinstance(cart_items, list) or len(cart_items) == 0:
            user_type = 'student_id' if 'student_id' in session else 'instructor_id'
            user_id = session.get('student_id') or session.get('instructor_id')
            if user_type == 'student_id':
                cursor.execute("""
                    SELECT m.name, ci.quantity
                    FROM cart_items ci
                    JOIN merchandise m ON ci.item_id = m.id
                    WHERE ci.student_id = %s
                """, (user_id,))
            else:
                cursor.execute("""
                    SELECT m.name, ci.quantity
                    FROM cart_items ci
                    JOIN merchandise m ON ci.item_id = m.id
                    WHERE ci.instructor_id = %s
                """, (user_id,))
            rows = cursor.fetchall()
            cart_items = [{'name': r['name'], 'quantity': r['quantity']} for r in rows]

        if not isinstance(cart_items, list) or len(cart_items) == 0:
            return jsonify({'error': 'Cart is empty'}), 400
        
        try:
            # Build order items by mapping cart item names to merchandise IDs/prices.
            order_items = []
            total_amount = 0.0

            for raw_item in cart_items:
                name = (raw_item or {}).get('name')
                quantity = int((raw_item or {}).get('quantity') or 0)
                if not name or quantity <= 0:
                    return jsonify({'error': 'Invalid cart item data'}), 400

                # Normalize name because the UI hardcodes item names (some include trailing spaces).
                normalized_name = " ".join(str(name).strip().split())
                cursor.execute(
                    "SELECT id, price, stock FROM merchandise WHERE LOWER(TRIM(name)) = LOWER(%s)",
                    (normalized_name,),
                )
                merch = cursor.fetchone()
                if not merch:
                    return jsonify({'error': f'Item not found in database: {normalized_name}'}), 400

                if merch['stock'] is not None and int(merch['stock']) < quantity:
                    return jsonify({'error': f'Not enough stock for: {normalized_name}'}), 400

                price = float(merch['price'])
                line_total = price * quantity
                total_amount += line_total
                order_items.append({'item_id': merch['id'], 'quantity': quantity, 'price': price})

            # Create order.
            # Your local DB schema may include additional NOT NULL columns (e.g., payment_method),
            # so we detect available columns and build the INSERT accordingly.
            cursor.execute("SHOW COLUMNS FROM orders")
            order_columns = {col["Field"] for col in cursor.fetchall()}

            insert_cols = []
            insert_vals = []

            # Required in all known schemas — choose column based on actual session type
            user_type = 'student' if 'student_id' in session else 'instructor'
            if user_type == 'student' and "student_id" in order_columns:
                insert_cols.append("student_id")
                insert_vals.append(buyer_id)
            elif user_type == 'instructor' and "instructor_id" in order_columns:
                insert_cols.append("instructor_id")
                insert_vals.append(buyer_id)
            elif "student_id" in order_columns:
                insert_cols.append("student_id")
                insert_vals.append(buyer_id)
            elif "instructor_id" in order_columns:
                insert_cols.append("instructor_id")
                insert_vals.append(buyer_id)

            if "total_amount" in order_columns:
                insert_cols.append("total_amount")
                insert_vals.append(total_amount)

            if "status" in order_columns:
                insert_cols.append("status")
                insert_vals.append("Pending")

            # Optional but commonly required fields
            if "payment_method" in order_columns:
                insert_cols.append("payment_method")
                insert_vals.append(payment_method)
            if "delivery_option" in order_columns:
                insert_cols.append("delivery_option")
                insert_vals.append(delivery_option)
            if "delivery_address" in order_columns:
                insert_cols.append("delivery_address")
                insert_vals.append(delivery_address)

            if not insert_cols:
                return jsonify({"error": "Orders table has no compatible columns"}), 500

            placeholders = ", ".join(["%s"] * len(insert_cols))
            columns_sql = ", ".join(insert_cols)
            cursor.execute(
                f"INSERT INTO orders ({columns_sql}) VALUES ({placeholders})",
                tuple(insert_vals),
            )
            
            order_id = cursor.lastrowid
            
            # Add order items
            for item in order_items:
                cursor.execute(
                    "INSERT INTO order_items (order_id, item_id, quantity, price) VALUES (%s, %s, %s, %s)",
                    (order_id, item['item_id'], item['quantity'], item['price']),
                )
                cursor.execute(
                    "UPDATE merchandise SET stock = stock - %s WHERE id = %s",
                    (item['quantity'], item['item_id']),
                )
            
            # Commit transaction
            conn.commit()
            
            return jsonify({
                'success': True,
                'message': 'Order processed successfully',
                'order_id': order_id
            })
            
        except Exception as e:
            # Rollback transaction on error
            conn.rollback()
            raise e
            
    except Exception as e:
        print(f"[process_order ERROR] {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Admin Dashboard Route
@app.route('/admin/dashboard')
def admin_dashboard():
    # Check if user is logged in and is admin
    if 'student_id' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect('/')
    
    if not _is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')
    
    try:
        # Connect to database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Get student statistics
        cursor.execute("SELECT COUNT(*) as total_students FROM students WHERE course != 'admin'")
        total_students = cursor.fetchone()['total_students']

        # Merchandise stats + listing for the Products Management table (AdminDashboard.html)
        category_col = _merch_category_column(cursor)
        cursor.execute("SELECT COUNT(*) AS total_products FROM merchandise")
        total_products = cursor.fetchone()['total_products']

        cursor.execute("SELECT COUNT(*) AS total_orders FROM orders WHERE NOT (status = 'Completed' AND payment_status = 'Success')")
        total_orders = cursor.fetchone()['total_orders']

        cursor.execute("SELECT COALESCE(SUM(amount), 0) AS total_revenue FROM payments WHERE status = 'Success'")
        total_revenue = float(cursor.fetchone()['total_revenue'] or 0)

        cursor.execute(
            f"""
            SELECT
                id,
                name,
                price,
                stock,
                image_url,
                {category_col} AS category
            FROM merchandise
            ORDER BY id DESC
            """
        )
        products = cursor.fetchall()

        cursor.execute(
            f"""
            SELECT
                id,
                name,
                price,
                stock,
                image_url,
                {category_col} AS category
            FROM merchandise
            WHERE stock <= 5
            ORDER BY stock ASC, id DESC
            """
        )
        low_stock_products = cursor.fetchall()
        
        # Get recent users
        cursor.execute("""
            SELECT * FROM students 
            WHERE course != 'admin' 
            ORDER BY created_at DESC 
            LIMIT 5
        """)
        recent_users = cursor.fetchall()
        
        cursor.execute(
            """
            SELECT
                o.id,
                o.total_amount,
                o.status,
                o.payment_status,
                o.payment_method,
                o.created_at,
                COALESCE(s.first_name, '') AS first_name,
                COALESCE(s.last_name, o.student_id) AS last_name
            FROM orders o
            LEFT JOIN students s ON s.student_id = o.student_id
            ORDER BY o.created_at DESC
            LIMIT 10
            """
        )
        recent_orders = cursor.fetchall()

        for order in recent_orders:
            cursor.execute(
                """
                SELECT
                    oi.quantity,
                    COALESCE(m.name, 'Unknown item') AS product_name
                FROM order_items oi
                LEFT JOIN merchandise m ON m.id = oi.item_id
                WHERE oi.order_id = %s
                """,
                (order["id"],),
            )
            order["order_items"] = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                p.id,
                p.amount,
                p.payment_method,
                p.reference_number,
                p.status,
                p.payment_date,
                COALESCE(e.full_name, p.email) AS instructor_name
            FROM payments p
            LEFT JOIN educators e ON e.email = p.email
            ORDER BY p.payment_date DESC
            LIMIT 10
            """
        )
        recent_payments = cursor.fetchall()

        # Normalize product image URLs
        for p in products:
            img = p.get('image_url') or ''
            if img and not img.startswith('/'):
                p['image_url'] = f'/static/images/{img}'
        for p in low_stock_products:
            img = p.get('image_url') or ''
            if img and not img.startswith('/'):
                p['image_url'] = f'/static/images/{img}'

        return render_template('AdminDashboard.html',
                            total_students=total_students,
                            total_products=total_products,
                            total_orders=total_orders,
                            total_revenue=total_revenue,
                            products=products,
                            low_stock_products=low_stock_products,
                            recent_orders=recent_orders,
                            recent_users=recent_users,
                            recent_payments=recent_payments)
        
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/admin/users')
def admin_users():
    if not _is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                student_id AS account_id,
                first_name,
                last_name,
                email,
                course,
                created_at
            FROM students
            WHERE course != 'admin'
            ORDER BY created_at DESC
            """
        )
        student_users = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                CAST(id AS CHAR) AS account_id,
                full_name,
                email,
                institution,
                subject,
                created_at
            FROM educators
            ORDER BY created_at DESC
            """
        )
        instructor_users = cursor.fetchall()

        return render_template(
            'AdminUsers.html',
            student_users=student_users,
            instructor_users=instructor_users,
            total_students=len(student_users),
            total_instructors=len(instructor_users),
            total_users=len(student_users) + len(instructor_users),
        )
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/admin/dashboard')
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/admin/orders')
def admin_orders():
    if not _is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                o.id,
                o.student_id,
                o.instructor_id,
                o.total_amount,
                LOWER(o.status) AS status,
                o.payment_status,
                o.payment_method,
                o.delivery_option,
                o.delivery_address,
                o.created_at,
                COALESCE(s.first_name, '') AS first_name,
                COALESCE(s.last_name, o.student_id) AS last_name,
                s.email AS student_email,
                COALESCE(e.full_name, o.instructor_id) AS instructor_name,
                e.email AS instructor_email,
                p.id AS payment_id,
                p.reference_number AS payment_ref,
                p.payment_date AS payment_date
            FROM orders o
            LEFT JOIN students s ON s.student_id = o.student_id
            LEFT JOIN educators e ON e.id = o.instructor_id
            LEFT JOIN payments p ON p.reference_number = CONCAT('ORD-', o.id)
            WHERE NOT (o.status = 'Completed' AND o.payment_status = 'Success')
            ORDER BY o.created_at DESC, o.id DESC
            """
        )
        orders = cursor.fetchall()

        for order in orders:
            cursor.execute(
                """
                SELECT
                    oi.quantity,
                    oi.price,
                    COALESCE(m.name, 'Unknown item') AS product_name
                FROM order_items oi
                LEFT JOIN merchandise m ON m.id = oi.item_id
                WHERE oi.order_id = %s
                """,
                (order["id"],),
            )
            order["order_items"] = cursor.fetchall()

        # Count successful payments from payments table
        cursor.execute(
            "SELECT COUNT(*) AS count FROM payments WHERE status = 'Success'"
        )
        successful_payments_count = cursor.fetchone()['count']

        # Fetch all payments for the payments section
        cursor.execute(
            """
            SELECT
                p.id,
                p.email,
                p.amount,
                p.payment_method,
                p.reference_number,
                p.status,
                p.payment_date
            FROM payments p
            ORDER BY p.payment_date DESC, p.id DESC
            """
        )
        payments = cursor.fetchall()

        return render_template('AdminOrders.html', orders=orders, payments=payments, successful_payments_count=successful_payments_count)
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/admin/dashboard')
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/admin/payments')
def admin_payments():
    if not _is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                p.id,
                p.email,
                p.amount,
                p.payment_method,
                p.reference_number,
                p.status,
                p.payment_date,
                o.id AS order_id,
                COALESCE(s.first_name, '') AS first_name,
                COALESCE(s.last_name, o.student_id) AS last_name,
                COALESCE(e.full_name, o.instructor_id) AS instructor_name
            FROM payments p
            LEFT JOIN orders o ON CONCAT('ORD-', o.id) = p.reference_number
            LEFT JOIN students s ON s.student_id = o.student_id
            LEFT JOIN educators e ON e.id = o.instructor_id
            ORDER BY p.payment_date DESC, p.id DESC
            """
        )
        payments = cursor.fetchall()

        # Stats
        total_payments = len(payments)
        success_count = sum(1 for p in payments if p.get('status') == 'Success')
        pending_count = sum(1 for p in payments if p.get('status') == 'Pending')
        total_revenue = sum(p.get('amount', 0) for p in payments if p.get('status') == 'Success')

        return render_template('AdminPayments.html', payments=payments, total_payments=total_payments, success_count=success_count, pending_count=pending_count, total_revenue=total_revenue)
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/admin/dashboard')
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# Admin Product Management Routes
@app.route('/admin/products', methods=['GET', 'POST'])
def admin_products():
    if not _is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')

    # POST handles both "add" and "edit" coming from AdminDashboard.html modals.
    if request.method == 'POST':
        conn = None
        cursor = None
        try:
            product_id_raw = request.form.get('product_id')
            name = (request.form.get('name') or '').strip()
            description = (request.form.get('description') or '').strip()
            price = float(request.form.get('price') or 0)
            stock = int(request.form.get('stock') or 0)
            category = (request.form.get('category') or '').strip()

            if not name or price < 0 or stock < 0 or not category:
                flash('Please provide valid product details.', 'danger')
                return redirect('/admin/dashboard')

            # Handle image upload (optional on edit, required on add in the template)
            image = request.files.get('image')
            image_url = None
            if image and image.filename:
                upload_folder = os.path.join('static', 'uploads', 'products')
                os.makedirs(upload_folder, exist_ok=True)
                filename = secure_filename(image.filename)
                image_path = os.path.join(upload_folder, filename)
                image.save(image_path)
                image_url = f'/static/uploads/products/{filename}'

            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor(dictionary=True)
            category_col = _merch_category_column(cursor)

            if product_id_raw:
                # Update existing merchandise item
                product_id = int(product_id_raw)
                if image_url:
                    cursor.execute(
                        f"""
                        UPDATE merchandise
                        SET name=%s, description=%s, price=%s, stock=%s, {category_col}=%s, image_url=%s
                        WHERE id=%s
                        """,
                        (name, description, price, stock, category, image_url, product_id),
                    )
                else:
                    cursor.execute(
                        f"""
                        UPDATE merchandise
                        SET name=%s, description=%s, price=%s, stock=%s, {category_col}=%s
                        WHERE id=%s
                        """,
                        (name, description, price, stock, category, product_id),
                    )
                conn.commit()
                flash('Merchandise item updated successfully!', 'success')
                return redirect('/admin/dashboard')

            # Add new merchandise item
            cursor.execute(
                f"""
                INSERT INTO merchandise (name, description, price, stock, {category_col}, image_url)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (name, description, price, stock, category, image_url),
            )
            conn.commit()
            flash('Merchandise item added successfully!', 'success')
            return redirect('/admin/dashboard')
        except Exception as e:
            flash(f'Error saving merchandise item: {str(e)}', 'danger')
            return redirect('/admin/dashboard')
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

    # GET: dedicated admin products section/page
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        category_col = _merch_category_column(cursor)
        cursor.execute(
            f"""
            SELECT
                id,
                name,
                description,
                price,
                stock,
                image_url,
                {category_col} AS category
            FROM merchandise
            ORDER BY id DESC
            """
        )
        products = cursor.fetchall()
        total_products = len(products)
        low_stock_count = sum(1 for p in products if p['stock'] <= 5)
        total_categories = len(set(p['category'] for p in products if p['category']))
        return render_template('AdminProducts.html', products=products, total_products=total_products, low_stock_count=low_stock_count, total_categories=total_categories)
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/admin/dashboard')
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/admin/products/<int:product_id>/delete', methods=['POST'])
def admin_delete_product(product_id: int):
    if not _is_admin():
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')

    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM merchandise WHERE id=%s", (product_id,))
        conn.commit()
        flash('Merchandise item deleted.', 'success')
        return redirect('/admin/dashboard')
    except Exception as e:
        flash(f'Error deleting item: {e}', 'danger')
        return redirect('/admin/dashboard')
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    identifier = request.form.get('identifier')

    # Connect to the database
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if the identifier exists in the database
        cursor.execute("SELECT * FROM students WHERE student_id = %s OR email = %s", (identifier, identifier))
        user = cursor.fetchone()

        if user:
            # Generate a 6-digit OTP
            otp = random.randint(100000, 999999)

            # Save the OTP in the database (for example, in a 'password_resets' table)
            cursor.execute(
                "INSERT INTO password_resets (user_id, otp) VALUES (%s, %s) "
                "ON DUPLICATE KEY UPDATE otp = %s",
                (user['student_id'], otp, otp)
            )
            conn.commit()

            # Send the OTP via email
            send_email(user['email'], "Password Reset OTP",
                    f"Your OTP for resetting your password is: {otp}")

            flash('An OTP has been sent to your email.', 'success')
            return redirect(f'/reset_password/{user["student_id"]}')
        else:
            flash('No account found with the provided information.', 'danger')

    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect('/')

@app.route('/reset_password/<user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    if request.method == 'POST':
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(f'/reset_password/{user_id}')

        # Verify the OTP
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("SELECT * FROM password_resets WHERE user_id = %s AND otp = %s",
                        (user_id, otp))
            reset_request = cursor.fetchone()

            if reset_request:
                # Hash the new password
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

                # Update the password in the database
                cursor.execute("UPDATE students SET password = %s WHERE student_id = %s",
                            (hashed_password, user_id))
                conn.commit()

                # Delete the reset request after successful password change
                cursor.execute("DELETE FROM password_resets WHERE user_id = %s", (user_id,))
                conn.commit()

                flash('Your password has been reset successfully.', 'success')
                return redirect('/')
            else:
                flash('Invalid or expired OTP.', 'danger')
                return redirect(f'/reset_password/{user_id}')
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", 'danger')
        except Exception as e:
            flash(f"An error occurred: {e}", 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('ResetPassword.html', user_id=user_id)

def generate_and_send_otp(user_id, email):
    otp = random.randint(100000, 999999)
    # Save OTP in the database (password_resets table or a new table)
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO email_otps (user_id, otp) VALUES (%s, %s) "
        "ON DUPLICATE KEY UPDATE otp = %s",
        (user_id, otp, otp)
    )
    conn.commit()
    cursor.close()
    conn.close()
    # Send OTP via email
    send_email(email, "Your OTP Code", f"Your OTP is: {otp}")

@app.route('/verify_otp/<user_id>', methods=['GET', 'POST'])
def verify_otp(user_id):
    if request.method == 'POST':
        otp = request.form.get('otp')
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM email_otps WHERE user_id = %s AND otp = %s", (user_id, otp))
        record = cursor.fetchone()
        if record:
            # OTP is correct, delete it and proceed
            cursor.execute("DELETE FROM email_otps WHERE user_id = %s", (user_id,))
            conn.commit()
            cursor.close()
            conn.close()
            flash('OTP verified successfully!', 'success')
            # Log the user in or redirect as needed
            return redirect('/')
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            cursor.close()
            conn.close()
            return redirect(f'/verify_otp/{user_id}')
    return render_template('VerifyOTP.html', user_id=user_id)

@app.route('/features_simple')
def features_simple():
    return render_template('Features.html')

@app.route('/appspecific/<path:filename>')
def appspecific(filename):
    return send_from_directory(os.path.join(app.root_path, 'appspecific'), filename)

@app.route('/clear_signup_success', methods=['POST'])
def clear_signup_success():
    session.pop('signup_success', None)
    return '', 204  # Return a 204 No Content response

@app.route('/my_purchases')
def my_purchases():
    try:
        student_id = session.get('student_id')
        if not student_id:
            flash('Please log in to view your purchases.', 'warning')
            return redirect(url_for('index'))

        first_name = session.get('first_name', 'Student')
        user_initials = ''.join([name[0].upper() for name in first_name.split() if name])

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Show purchases for this student (orders + order_items + merchandise).
        query = """
            SELECT 
                o.id AS order_id,
                o.total_amount,
                o.status,
                o.payment_status,
                o.payment_method,
                o.created_at,
                oi.quantity,
                oi.price,
                m.name AS item_name,
                m.image_url,
                (SELECT p.reference_number FROM payments p WHERE p.reference_number = CONCAT('ORD-', o.id) LIMIT 1) AS reference_number
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            LEFT JOIN merchandise m ON oi.item_id = m.id
            WHERE o.student_id = %s
            ORDER BY o.created_at DESC, o.id DESC
        """
        cursor.execute(query, (student_id,))
        purchases = cursor.fetchall()

        # Normalize image URLs to full static paths
        for row in purchases:
            img = row.get('image_url') or ''
            if img and not img.startswith('/'):
                row['image_url'] = f'/static/images/{img}'

        cursor.close()
        conn.close()

        return render_template(
            'MyPurchases.html',
            student_id=student_id,
            first_name=first_name,
            user_initials=user_initials,
            purchases=purchases
        )
    except Exception as e:
        flash('Could not load purchases.', 'danger')
        return redirect(url_for('index'))


@app.route('/orders/<int:order_id>/refund', methods=['POST'])
def request_refund(order_id: int):
    try:
        student_id = session.get('student_id')
        if not student_id:
            flash('Please log in to request a refund.', 'warning')
            return redirect(url_for('index'))

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Ensure the order belongs to this student
        cursor.execute(
            "SELECT id, payment_status FROM orders WHERE id = %s AND student_id = %s",
            (order_id, student_id),
        )
        order = cursor.fetchone()
        if not order:
            flash('Order not found.', 'danger')
            return redirect(url_for('my_purchases'))

        payment_status = (order.get('payment_status') or 'Pending')
        if payment_status in {'Success', 'Refunded'}:
            flash('This order is not eligible for refund.', 'warning')
            return redirect(url_for('my_purchases'))

        # Mark as refund requested
        cursor.execute(
            "UPDATE orders SET payment_status = 'Refund Requested' WHERE id = %s",
            (order_id,),
        )
        conn.commit()
        flash('Refund request submitted. Please wait for confirmation.', 'success')
        return redirect(url_for('my_purchases'))
    except Exception as e:
        flash(f'Could not request refund: {e}', 'danger')
        return redirect(url_for('my_purchases'))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/instructor/my_purchases')
def instructor_my_purchases():
    try:
        # Check if instructor is logged in
        if 'email' not in session:
            flash('Please log in to access the dashboard.', 'warning')
            return redirect('/')

        instructor_email = session.get('email')
        
        # Connect to database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Query orders table for instructor purchases (process_order stores here)
        query = """
            SELECT 
                o.id AS order_id,
                o.total_amount,
                o.payment_status,
                o.status,
                o.payment_method,
                o.delivery_option,
                o.delivery_address,
                o.created_at,
                oi.quantity,
                oi.price,
                m.name AS item_name,
                m.image_url,
                (SELECT p.reference_number FROM payments p WHERE p.reference_number = CONCAT('ORD-', o.id) LIMIT 1) AS reference_number
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            LEFT JOIN merchandise m ON oi.item_id = m.id
            WHERE o.instructor_id = %s
            ORDER BY o.created_at DESC, o.id DESC
        """
        cursor.execute(query, (session.get('instructor_id'),))
        rows = cursor.fetchall()

        # Group rows by order for template rendering
        purchases = []
        order_map = {}
        for row in rows:
            oid = row['order_id']
            if oid not in order_map:
                order_map[oid] = {
                    'order_id': oid,
                    'total_amount': float(row['total_amount'] or 0),
                    'status': row['status'],
                    'payment_status': row['payment_status'],
                    'payment_method': row['payment_method'],
                    'delivery_option': row['delivery_option'],
                    'delivery_address': row['delivery_address'],
                    'created_at': row['created_at'],
                    'reference_number': row.get('reference_number') or '',
                    'image_url': '',
                    'order_items': []
                }
            if row['item_name']:
                img = row.get('image_url') or ''
                if img and not img.startswith('/'):
                    img = f'/static/images/{img}'
                order_map[oid]['order_items'].append({
                    'name': row['item_name'],
                    'quantity': row['quantity'],
                    'price': float(row['price'] or 0),
                    'image_url': img
                })
                # Use first item's image for the order card
                if not order_map[oid]['image_url']:
                    order_map[oid]['image_url'] = img
        purchases = list(order_map.values())

        cursor.close()
        conn.close()

        # Get instructor's full name from session
        full_name = session.get('full_name', 'Instructor')
        user_initials = ''.join([name[0].upper() for name in full_name.split() if name])

        return render_template('InstructorMyPurchases.html',
                       purchases=purchases,
                       full_name=full_name,
                       user_initials=user_initials)
    except Exception as e:
        print(f"Database error: {str(e)}")
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/')

@app.route('/some_route')
def some_route():
    # Get user info from session
    first_name = session.get('first_name')
    student_id = session.get('student_id')
    
    # Calculate user initials
    full_name = f"{session.get('first_name', '')} {session.get('last_name', '')}"
    user_initials = ''.join([name[0] for name in full_name.split() if name])
    
    return render_template('template.html',
                        first_name=first_name,
                        student_id=student_id,
                        user_initials=user_initials)

@app.route('/blog')
def blog():
    return render_template('BlogSection.html',)

@app.route('/features')
def features():
    try:
        # Get user info from session
        user_info = {
            'full_name': session.get('full_name', 'Guest'),
            'email': session.get('email', ''),
            'is_authenticated': 'email' in session or 'student_id' in session,
            'user_initials': ''.join([name[0].upper() for name in session.get('full_name', 'Guest').split() if name])
        }
        
        return render_template('Features.html', user=user_info)
    except Exception as e:
        print(f"Error in features route: {str(e)}")
        flash('Error accessing features page', 'error')
        return redirect(url_for('index'))

@app.route('/appspecific/com.chrome.devtools.json')
def chrome_devtools():
    return jsonify({
        "version": "1.0",
        "enabled": True,
        "allowedOrigins": [
            "*"
        ]
    }), 200, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
    }

# Add this with your other routes
@app.route('/visual-aid')
def visual_aid():
    return render_template('VisualAid.html')
def _ensure_schema():
    """Auto-migrate: ensure cart_items and orders support instructors."""
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Ensure cart_items table exists with both student_id and instructor_id
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cart_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id VARCHAR(50) NULL,
                instructor_id INT NULL,
                item_id INT NOT NULL,
                quantity INT NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_cart_student_item (student_id, item_id),
                UNIQUE KEY uq_cart_instructor_item (instructor_id, item_id),
                FOREIGN KEY (item_id) REFERENCES merchandise(id) ON DELETE CASCADE
            )
        """)

        # If table already existed without instructor_id, add it
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'cart_items'
              AND column_name = 'instructor_id'
        """)
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                ALTER TABLE cart_items
                ADD COLUMN instructor_id INT NULL AFTER student_id,
                ADD UNIQUE KEY uq_cart_instructor_item (instructor_id, item_id)
            """)

        # Ensure orders table can store instructor purchases
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'orders'
              AND column_name = 'instructor_id'
        """)
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                ALTER TABLE orders
                ADD COLUMN instructor_id INT NULL AFTER student_id
            """)

        # Make student_id nullable so instructors can place orders without it
        cursor.execute("""
            SELECT is_nullable FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'orders'
              AND column_name = 'student_id'
        """)
        row = cursor.fetchone()
        if row and row[0] == 'NO':
            cursor.execute("""
                ALTER TABLE orders
                MODIFY COLUMN student_id VARCHAR(50) NULL
            """)

        conn.commit()
    except Exception as e:
        print(f"Schema migration warning (non-fatal): {e}")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


# Run lightweight schema check once at import time
_ensure_schema()

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='192.168.1.59')