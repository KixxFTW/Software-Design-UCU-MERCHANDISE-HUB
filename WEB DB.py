<<<<<<< HEAD
from flask import Flask, render_template, request, redirect, url_for, flash
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flashing messages

# Function to connect to the database
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="127.0.0.1",  # Replace with your database host
            user="root",       # Replace with your database user
            password="Admin",  # Replace with your database password
            database="usersdb" # Replace with your database name
        )
        if conn.is_connected():
            return conn
    except Error as e:
        print(f"Error: {e}")
        return None

# Route to display the HTML form
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle login
@app.route('/login', methods=['POST'])
def login():
    student_id = request.form['student_id']
    password = request.form['password']
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection failed')
        return render_template('index.html')  # Stay on the login page
    
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE student_id = %s AND password = %s', (student_id, password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid student ID or password')
        return render_template('index.html')  # Stay on the login page

# Route to display the dashboard after successful login
@app.route('/dashboard')
def dashboard():
    return render_template('Dashboard.html')

if __name__ == '__main__':
=======
from flask import Flask, render_template, request, redirect, url_for, flash
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)
app.secret_key = 'F9835XTG'  
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="127.0.0.1", 
            user="root",       
            password="Admin",  
            database="users"   
        )
        if conn.is_connected():
            return conn
    except Error as e:
        print(f"Error: {e}")
        return None

#Route to display the HTML
@app.route('/')
def index():
    return render_template('index.html')

#Route to handle login
@app.route('/login', methods=['POST'])
def login():
    student_id = request.form['student_id']
    password = request.form['password']
    
    conn = get_db_connection()
    if conn is None:
        flash('Database connection failed')
        return render_template('index.html') 
    
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE student_id = %s AND password = %s', (student_id, password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid student ID or password')
        return render_template('index.html')

#display the dashboard after successful login
@app.route('/dashboard')
def dashboard():
    return render_template('Dashboard.html')

if __name__ == '__main__':
>>>>>>> origin/main
    app.run(debug=True)