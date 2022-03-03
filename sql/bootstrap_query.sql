DROP DATABASE IF EXISTS surer_carpark;

CREATE DATABASE surer_carpark;
USE surer_carpark;

DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
    `email` VARCHAR(256) NOT NULL,
    `hashed_password` VARCHAR(256),
    `salt` VARCHAR(256),
    `first_name` VARCHAR(256) NOT NULL,
    `last_name` VARCHAR(256) NOT NULL,
    `contact_no` CHAR(8) NOT NULL,
    PRIMARY KEY (`email`)
);

-- import sessions
DROP TABLE IF EXISTS `sessions`;
CREATE TABLE `sessions` (
    `user_email` VARCHAR(256) NOT NULL,
    `session_id` VARCHAR(256) NOT NULL,

    PRIMARY KEY (`user_email`, `session_id`),
    FOREIGN KEY (`user_email`) REFERENCES `user` (`email`)
);
