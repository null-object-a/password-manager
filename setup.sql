BEGIN TRANSACTION;
CREATE DATABASE password_manager;
USE password_manager;
CREATE TABLE passwd(
    id INT NOT NULL AUTO INCREMENT,
    host VARCHAR(256) NOT NULL,
    login_candidate VARCHAR(256) NOT NULL,
    password VARCHAR(3000) NOT NULL, 
    PRIMARY KEY(id)
);
COMMIT TRANSACTION;
CREATE USER 'passwd_admin'@'localhost' IDENTIFIED BY '$PASSWORD';
GRANT ALL PRIVILEDGES ON password_manager . * TO USER 'passwd_admin'@'localhost';
FLUSH PRIVILEDGES;