CREATE DATABASE IF NOT EXISTS user_database;
USE user_database;


CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


INSERT INTO users (student_id, password) VALUES 
('20231466', 'F9835XTG' ),
('20231467', 'password456' ),
('20231468', 'password789');


SELECT * FROM users;


UPDATE users SET password = '123' WHERE id = 1;


DELETE FROM users WHERE id = 3;


SELECT * FROM users;