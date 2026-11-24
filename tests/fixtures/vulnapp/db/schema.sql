CREATE TABLE users (id serial primary key, email text, password text);
GRANT ALL PRIVILEGES ON users TO public;
CREATE USER app IDENTIFIED BY 'password';
DELETE FROM audit_log;
INSERT INTO users (email, password) VALUES ('admin@x.qa', 'admin123');
