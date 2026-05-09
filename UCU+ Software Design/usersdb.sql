CREATE TABLE password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    INDEX (token),
    INDEX (email)
);

CREATE TABLE students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    student_id VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    course VARCHAR(100),
    google_id VARCHAR(255) UNIQUE,
    google_email VARCHAR(255) UNIQUE,
    google_password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE educators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    institution VARCHAR(100),
    subject VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    google_id VARCHAR(255) UNIQUE,
    google_email VARCHAR(255) UNIQUE,
    google_password VARCHAR(255)
);

DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;

CREATE TABLE merchandise (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    stock INT NOT NULL,
    image_url VARCHAR(255),
    catergory VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_merchandise_name (name)
);

CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(50) NULL,
    instructor_id INT NULL,
    total_amount DECIMAL(10, 2) NOT NULL,
    payment_method VARCHAR(50) NOT NULL,
    delivery_option VARCHAR(50),
    delivery_address VARCHAR(255),
    payment_status ENUM('Pending', 'Success', 'Failed', 'Refund Requested', 'Refunded') DEFAULT 'Pending',
    status ENUM('Pending', 'Completed', 'Cancelled') DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE order_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    item_id INT NOT NULL,
    quantity INT NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES merchandise(id) ON DELETE CASCADE
);

CREATE TABLE cart_items (
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
);

-- Seed initial merchandise matching the hardcoded items in templates/Dashboard.html.
-- (Your checkout maps cart item `name` -> `merchandise.name`.)
INSERT INTO merchandise (name, description, price, stock, image_url, catergory, created_at) VALUES
('Computer Engineering Shirt', 'Department shirt', 700.00, 100, 'CPE.jpg', 'Shirt', CURRENT_TIMESTAMP),
('Computer Engineering ID Lace', 'Department ID lace', 100.00, 100, 'LACE CPE.jpg', 'Lace', CURRENT_TIMESTAMP),
('Computer Engineering Bundle', 'Shirt + lace bundle', 850.00, 100, 'CEA CPE Bundle.png', 'Bundle', CURRENT_TIMESTAMP),
('Civil Engineering Shirt', 'Department shirt', 700.00, 100, 'CE.jpg', 'Shirt', CURRENT_TIMESTAMP),
('Civil Engineering ID Lace', 'Department ID lace', 100.00, 100, 'LACE CE.jpg', 'Lace', CURRENT_TIMESTAMP),
('Civil Engineering Bundle', 'Shirt + lace bundle', 850.00, 100, 'CEA CE Bundle.png', 'Bundle', CURRENT_TIMESTAMP),
('Electrical Engineering Shirt', 'Department shirt', 700.00, 100, 'EE.jpg', 'Shirt', CURRENT_TIMESTAMP),
('Electrical Engineering ID Lace', 'Department ID lace', 100.00, 100, 'LACE EE.jpg', 'Lace', CURRENT_TIMESTAMP),
('JEAS Shirt', 'Department shirt', 400.00, 100, 'CEA.jpg', 'Shirt', CURRENT_TIMESTAMP),
('JEAS ID Lace', 'Department ID lace', 100.00, 100, 'LACE JEAS.jpg', 'Lace', CURRENT_TIMESTAMP),
('Architecture ID Lace', 'Department ID lace', 100.00, 100, 'LACE ARCHI.jpg', 'Lace', CURRENT_TIMESTAMP),
('CEA JEAS Water Bottle', 'Water bottle', 700.00, 100, 'CEA JEAS Bottle.png', 'Accessory', CURRENT_TIMESTAMP),
('JEAS Complete Bundle', 'Complete bundle', 850.00, 100, 'CEA JEAS Bundle.png', 'Bundle', CURRENT_TIMESTAMP),
('CEA Maroon Sport Shirt', 'Sport shirt', 410.00, 100, 'CEA Maroon.jpg', 'Shirt', CURRENT_TIMESTAMP),
('CEA White Sport Shirt', 'Sport shirt', 410.00, 100, 'CEA White.jpg', 'Shirt', CURRENT_TIMESTAMP),
('Architecture Shirt', 'Department shirt', 700.00, 100, 'CEA ARCHI.jpg', 'Shirt', CURRENT_TIMESTAMP),
('Electronics Engineering Shirt', 'Department shirt', 700.00, 100, 'CEA ECE.png', 'Shirt', CURRENT_TIMESTAMP),
('Electronics Engineering ID Lace', 'Department ID lace', 100.00, 100, 'LACE ECE.png', 'Lace', CURRENT_TIMESTAMP)
ON DUPLICATE KEY UPDATE
  description = VALUES(description),
  price = VALUES(price),
  stock = VALUES(stock),
  image_url = VALUES(image_url),
  catergory = VALUES(catergory);
CREATE TABLE payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    payment_method VARCHAR(50) NOT NULL,
    reference_number VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'Pending',
    payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_status (status),
    INDEX idx_payment_date (payment_date)
);
CREATE TABLE IF NOT EXISTS notification_preferences (
  student_id VARCHAR(50) NOT NULL,
  email BOOLEAN NOT NULL DEFAULT TRUE,
  sms   BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (student_id),
  CONSTRAINT fk_notification_preferences_student
    FOREIGN KEY (student_id) REFERENCES students(student_id)
    ON DELETE CASCADE
);
