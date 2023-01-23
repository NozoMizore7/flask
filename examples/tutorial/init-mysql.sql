-- Initialize the database.
-- Drop any existing data and create empty tables.

CREATE DATABASE /*!32312 IF NOT EXISTS*/`flask` /*!40100 DEFAULT CHARACTER SET latin1 */;
USE `flask`;

DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS post;

CREATE TABLE `user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(45) NOT NULL,
  `password` varchar(255) NOT NULL,
  `contact_name` varchar(45) DEFAULT NULL,
  `email` varchar(45) DEFAULT NULL,
  `address1` varchar(45) DEFAULT NULL,
  `address2` varchar(45) DEFAULT NULL,
  `city` varchar(45) DEFAULT NULL,
  `state` varchar(20) DEFAULT NULL,
  `postal_code` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `new_tablecol_UNIQUE` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=latin1;

CREATE TABLE `post` (
  `id` int NOT NULL AUTO_INCREMENT,
  `author_id` int NOT NULL,
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `title` varchar(45) NOT NULL,
  `body` varchar(2000) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `author_id_user_id` (`author_id`),
  CONSTRAINT `author_id_user_id` FOREIGN KEY (`author_id`) REFERENCES `user` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=latin1;