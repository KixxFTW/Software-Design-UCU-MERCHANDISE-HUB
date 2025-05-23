from flask import Flask, request, redirect, render_template, flash, session, jsonify, url_for, send_from_directory, get_flashed_messages
import mysql.connector
import bcrypt
import os
import requests
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

# Database configuration
DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': 'Admin',
    'database': 'usersdb'
}

# Google OAuth2 configuration
GOOGLE_CLIENT_ID = '58628545651-m1hruo8queisfor55q52p25a5f9tk2p7.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'yGOCSPX-5MXPolQWVDNt0h-8d1xgIfd1AEgU'
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

# Example in-memory product list (replace with a database in production)
products = [
    {"id": 1, "name": "Computer Engineering Shirt", "price": 700, "image": "CEA CPE.png", "category": "Shirt", "stock": 10},
    {"id": 2, "name": "Computer Engineering ID Lace", "price": 100, "image": "LACE CPE.png", "category": "Lace", "stock": 50},
]

@app.route('/api/products', methods=['GET'])
def get_products():
    return jsonify(products)

@app.route('/api/products', methods=['POST'])
def add_product():
    new_product = request.json
    new_product['id'] = len(products) + 1
    products.append(new_product)
    return jsonify({"message": "Product added successfully"}), 201

@app.route('/api/products/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    data = request.json
    for product in products:
        if product['id'] == product_id:
            product.update(data)
            return jsonify({"message": "Product updated successfully"})
    return jsonify({"error": "Product not found"}), 404

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    global products
    products = [product for product in products if product['id'] != product_id]
    return jsonify({"message": "Product deleted successfully"})

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
        query = "INSERT INTO students (student_id, first_name, last_name, email, password) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (student_id, first_name, last_name, email, hashed_password))
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
    
    # Use the client to generate a request URI with state parameter to track instructor flow
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for('google_instructor_callback', _external=True),
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
                    INSERT INTO students (student_id, first_name, last_name, email, password, google_id, google_email, google_password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(query, (
                    google_id, 
                    first_name, 
                    last_name, 
                    email, 
                    hashed_password,
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
            email = user_info["email"]
            full_name = f"{user_info.get('given_name', '')} {user_info.get('family_name', '')}"
            google_id = user_info["sub"]
            
            # Check if instructor exists in database
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor(dictionary=True)
            query = "SELECT * FROM educators WHERE email = %s"
            cursor.execute(query, (email,))
            instructor = cursor.fetchone()
            
            if not instructor:
                # Generate a random password for the instructor
                random_password = os.urandom(16).hex()
                hashed_password = bcrypt.hashpw(random_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                # Store Google account information
                query = """
                    INSERT INTO educators (full_name, email, password, institution, subject, google_id, google_email, google_password)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(query, (
                    full_name,
                    email,
                    hashed_password,
                    "Institution not specified",
                    "Subject not specified",
                    google_id,
                    email,
                    hashed_password  # Store the hashed password for Google account
                ))
                conn.commit()
                
                # Get the newly created instructor
                query = "SELECT * FROM educators WHERE email = %s"
                cursor.execute(query, (email,))
                instructor = cursor.fetchone()
            session['instructor_id'] = instructor.get('id')
            session['full_name'] = instructor.get('full_name')
            session['email'] = instructor.get('email')
            session['institution'] = instructor.get('institution')
            session['is_instructor'] = True
            
            cursor.fetchall()  # Clear any unread results
            cursor.close()
            conn.close()
            
            flash(f'Welcome {full_name}! You have successfully logged in as an instructor.', 'success')
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
        query = "INSERT INTO students (student_id, first_name, last_name, email, password) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (
            user_info.get('sub'),  # Use Google user ID as student_id
            user_info.get('given_name'),
            user_info.get('family_name'),
            user_info.get('email'),
            empty_password_hash
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
        
        return render_template(
            'InstructorDashboard.html',  # You'll need to create this template
            full_name=session.get('full_name'),
            email=session.get('email'),
            institution=session.get('institution'),
            user_initials=initials,
            user_name=full_name
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
            return redirect(url_for('instructor_login'))

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
            ORDER BY p.payment_date DESC
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
    if 'instructor_id' not in session:
        return jsonify({'error': 'Please log in to add items to cart'}), 401
    
    try:
        data = request.get_json()
        item_id = data.get('item_id')
        quantity = data.get('quantity', 1)
        
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Get item details
        cursor.execute("SELECT * FROM merchandise WHERE id = %s", (item_id,))
        item = cursor.fetchone()
        
        if not item:
            return jsonify({'error': 'Item not found'}), 404
        
        # Add to cart in database
        cursor.execute("""
            INSERT INTO cart_items (instructor_id, item_id, quantity)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE quantity = quantity + %s
        """, (session['instructor_id'], item_id, quantity, quantity))
        
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
    if 'instructor_id' not in session:
        return jsonify({'error': 'Please log in to modify cart'}), 401
    
    try:
        data = request.get_json()
        item_id = data.get('item_id')
        
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM cart_items 
            WHERE instructor_id = %s AND item_id = %s
        """, (session['instructor_id'], item_id))
        
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
    if 'instructor_id' not in session:
        return jsonify({'error': 'Please log in to modify cart'}), 401
    
    try:
        data = request.get_json()
        item_id = data.get('item_id')
        quantity = data.get('quantity')
        
        if quantity < 1:
            return jsonify({'error': 'Quantity must be at least 1'}), 400
        
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE cart_items 
            SET quantity = %s 
            WHERE instructor_id = %s AND item_id = %s
        """, (quantity, session['instructor_id'], item_id))
        
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
    if 'instructor_id' not in session:
        return jsonify({'error': 'Please log in to view cart'}), 401
    
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT ci.*, m.name, m.price, m.image_url
            FROM cart_items ci
            JOIN merchandise m ON ci.item_id = m.id
            WHERE ci.instructor_id = %s
        """, (session['instructor_id'],))
        
        cart_items = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'cart_items': cart_items
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Order Processing Routes
@app.route('/process_order', methods=['POST'])
def process_order():
    if 'instructor_id' not in session:
        return jsonify({'error': 'Please log in to process order'}), 401
    
    try:
        data = request.get_json()
        payment_method = data.get('payment_method')
        delivery_option = data.get('delivery_option')
        delivery_address = data.get('delivery_address')
        
        if not all([payment_method, delivery_option, delivery_address]):
            return jsonify({'error': 'Missing required order information'}), 400
        
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Start transaction
        conn.start_transaction()
        
        try:
            # Get cart items
            cursor.execute("""
                SELECT ci.*, m.price
                FROM cart_items ci
                JOIN merchandise m ON ci.item_id = m.id
                WHERE ci.instructor_id = %s
            """, (session['instructor_id'],))
            cart_items = cursor.fetchall()
            
            if not cart_items:
                return jsonify({'error': 'Cart is empty'}), 400
            
            # Calculate total amount
            total_amount = sum(item['price'] * item['quantity'] for item in cart_items)
            
            # Create order
            cursor.execute("""
                INSERT INTO orders (instructor_id, total_amount, payment_method, delivery_option, delivery_address, status)
                VALUES (%s, %s, %s, %s, %s, 'Pending')
            """, (session['instructor_id'], total_amount, payment_method, delivery_option, delivery_address))
            
            order_id = cursor.lastrowid
            
            # Add order items
            for item in cart_items:
                cursor.execute("""
                    INSERT INTO order_items (order_id, item_id, quantity, price)
                    VALUES (%s, %s, %s, %s)
                """, (order_id, item['item_id'], item['quantity'], item['price']))
            
            # Clear cart
            cursor.execute("DELETE FROM cart_items WHERE instructor_id = %s", (session['instructor_id'],))
            
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
    
    if session.get('student_id') != 'ADMIN001' and session.get('course') != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')
    
    try:
        # Connect to database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Get student statistics
        cursor.execute("SELECT COUNT(*) as total_students FROM students WHERE course != 'admin'")
        total_students = cursor.fetchone()['total_students']
        
        # Get recent users
        cursor.execute("""
            SELECT * FROM students 
            WHERE course != 'admin' 
            ORDER BY created_at DESC 
            LIMIT 5
        """)
        recent_users = cursor.fetchall()
        
        return render_template('AdminDashboard.html',
                            total_students=total_students,
                            total_products=0,
                            total_orders=0,
                            total_revenue=0,
                            recent_orders=[],
                            recent_users=recent_users)
        
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Admin Product Management Routes
@app.route('/admin/products', methods=['GET', 'POST'])
def admin_edit_products():
    if 'student_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect('/')
    
    if session.get('student_id') != 'ADMIN001' and session.get('course') != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')
    
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            price = float(request.form.get('price'))
            stock = int(request.form.get('stock'))
            category = request.form.get('category')
            
            # Handle image upload
            image = request.files.get('image')
            image_url = None
            
            if image:
                # Ensure the upload folder exists
                upload_folder = os.path.join('static', 'uploads', 'products')
                os.makedirs(upload_folder, exist_ok=True)
                
                # Save the image
                filename = secure_filename(image.filename)
                image_path = os.path.join(upload_folder, filename)
                image.save(image_path)
                image_url = f'/static/uploads/products/{filename}'
            
            # Connect to database
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            
            # Insert product
            query = """
                INSERT INTO products (name, description, price, stock, category, image_url)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE description = %s, price = %s, stock = %s, category = %s, image_url = %s
            """
            cursor.execute(query, (name, description, price, stock, category, image_url, description, price, stock, category, image_url))
            conn.commit()
            
            # Log admin activity
            activity_query = """
                INSERT INTO admin_activity_log (admin_id, action, details)
                VALUES (%s, %s, %s)
            """
            activity_details = f"Added/Updated product: {name} (Category: {category}, Price: ₱{price})"
            cursor.execute(activity_query, (session['student_id'], 'add_update_product', activity_details))
            conn.commit()
            
            flash('Product added/updated successfully!', 'success')
            return redirect('/admin/dashboard')
            
        except Exception as e:
            flash(f'Error adding/updating product: {str(e)}', 'danger')
            return redirect('/admin/products/add')
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()
    
    return render_template('AdminEditProduct.html')

@app.route('/admin/products/edit', methods=['GET', 'POST'])
def admin_edit_product():
    if 'student_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect('/')

    if session.get('student_id') != 'ADMIN001' and session.get('course') != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')

    if request.method == 'POST':
        try:
            product_id = int(request.form.get('product_id'))
            name = request.form.get('name')
            price = float(request.form.get('price'))
            stock = int(request.form.get('stock'))
            category = request.form.get('category')

            image = request.files.get('image')
            image_url = None

            if image:
                upload_folder = os.path.join('static', 'uploads', 'products')
                os.makedirs(upload_folder, exist_ok=True)

                filename = secure_filename(image.filename)
                image_path = os.path.join(upload_folder, filename)
                image.save(image_path)
                image_url = f'/static/uploads/products/{filename}'

            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()

            query = """
                UPDATE products
                SET name = %s, price = %s, stock = %s, category = %s, image_url = %s
                WHERE id = %s
            """
            cursor.execute(query, (name, price, stock, category, image_url, product_id))
            conn.commit()

            activity_query = """
                INSERT INTO admin_activity_log (admin_id, action, details)
                VALUES (%s, %s, %s)
            """
            activity_details = f"Updated product: {name} (ID: {product_id})"
            cursor.execute(activity_query, (session['student_id'], 'edit_product', activity_details))
            conn.commit()

            flash('Product updated successfully!', 'success')
            return redirect('/admin/products/edit')

        except Exception as e:
            flash(f'Error updating product: {str(e)}', 'danger')
            return redirect('/admin/products/edit')
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        return render_template('AdminEditProduct.html', products=products)  # Ensure 'products' is passed
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/admin/dashboard')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.route('/admin/products', methods=['GET'])
def admin_products():
    # Check if the user is logged in and is an admin
    if 'student_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect('/')

    if session.get('student_id') != 'ADMIN001' and session.get('course') != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect('/')

    # Fetch all products to display in the admin products page
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        return render_template('AdminEditProduct.html', products=products)
    except Exception as e:
        flash(f"An error occurred: {e}", 'danger')
        return redirect('/admin/dashboard')
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
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
        first_name = session.get('first_name', 'Student')
        user_initials = ''.join([name[0].upper() for name in first_name.split() if name])
        # Fetch purchases from DB if needed, e.g.:
        # purchases = get_purchases_for_student(student_id)
        purchases = []  # Replace with actual data
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

@app.route('/instructor/my_purchases')
def instructor_my_purchases():
    try:
        # Check if instructor is logged in
        if 'email' not in session:
            flash('Please log in to access the dashboard.', 'warning')
            return redirect(url_for('instructor_login'))

        instructor_email = session.get('email')
        
        # Connect to database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Execute query using instructor's email
        query = """
            SELECT o.id AS order_id, o.total_amount, o.status, o.created_at,
                   oi.item_id, oi.quantity, oi.price, m.name AS item_name
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            LEFT JOIN merchandise m ON oi.item_id = m.id
            WHERE o.email = %s  
            ORDER BY o.created_at DESC
        """
        cursor.execute(query, (instructor_email,))
        purchases = cursor.fetchall()

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
        return redirect(url_for('instructor_login'))

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
if __name__ == '__main__':
    app.run(debug=True, port=5000)