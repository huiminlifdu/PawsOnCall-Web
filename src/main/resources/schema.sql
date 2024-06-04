drop table if exists t_user;

CREATE TABLE t_user (
  c_id INT PRIMARY KEY AUTO_INCREMENT,
  c_name VARCHAR(50),
  c_state VARCHAR(50),
  c_country VARCHAR(50)
);