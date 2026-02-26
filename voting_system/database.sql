-- Database Schema for BOA AMPONSEM SHS Voting System

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

-- Table: admin
CREATE TABLE IF NOT EXISTS `admin` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert default admin (username: admin, password: password123)
INSERT INTO `admin` (`id`, `username`, `password`) VALUES
(1, 'admin', '$2y$10$YRrxuNhtaBU4BfMq7zMH3OT69T3zNZnB/d3zT7REteCQJN14aa6J6');

-- Table: polling_stations
CREATE TABLE IF NOT EXISTS `polling_stations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `station_name` varchar(100) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table: classes
CREATE TABLE IF NOT EXISTS `classes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `class_name` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `class_name` (`class_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table: portfolios
CREATE TABLE IF NOT EXISTS `portfolios` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `portfolio_name` varchar(100) NOT NULL,
  `short_code` varchar(10) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `portfolio_name` (`portfolio_name`),
  UNIQUE KEY `short_code` (`short_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table: voters
CREATE TABLE IF NOT EXISTS `voters` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `voter_id` varchar(20) NOT NULL,
  `fullname` varchar(100) NOT NULL,
  `program` ENUM('Visual Arts', 'General Arts', 'Home Econs', 'Agric Science', 'General Science', 'Business') NOT NULL,
  `class_id` int(11) NOT NULL,
  `has_voted` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `voter_id` (`voter_id`),
  KEY `class_id` (`class_id`),
  CONSTRAINT `fk_voter_class` FOREIGN KEY (`class_id`) REFERENCES `classes` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table: candidates
CREATE TABLE IF NOT EXISTS `candidates` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `candidate_id` varchar(20) NOT NULL,
  `fullname` varchar(100) NOT NULL,
  `gender` ENUM('Boy', 'Girl') NOT NULL,
  `portfolio_id` int(11) NOT NULL,
  `photo` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `candidate_id` (`candidate_id`),
  KEY `portfolio_id` (`portfolio_id`),
  CONSTRAINT `fk_candidate_portfolio` FOREIGN KEY (`portfolio_id`) REFERENCES `portfolios` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table: votes
CREATE TABLE IF NOT EXISTS `votes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `voter_id` int(11) NOT NULL,
  `candidate_id` int(11) NOT NULL,
  `portfolio_id` int(11) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `voter_id` (`voter_id`),
  KEY `candidate_id` (`candidate_id`),
  KEY `portfolio_id` (`portfolio_id`),
  CONSTRAINT `fk_vote_voter` FOREIGN KEY (`voter_id`) REFERENCES `voters` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_vote_candidate` FOREIGN KEY (`candidate_id`) REFERENCES `candidates` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_vote_portfolio` FOREIGN KEY (`portfolio_id`) REFERENCES `portfolios` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

COMMIT;
