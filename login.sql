CREATE DATABASE loginDB;
USE loginDB;

CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL
);

INSERT INTO users (username, password) VALUES ('administrador', 'panyvino_sisenior5677');

SHOW DATABASES;
USE logindb;
SHOW TABLES;
SELECT * FROM users;
