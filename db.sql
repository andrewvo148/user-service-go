CREATE TABLE users (
  id bigserial PRIMARY KEY ,
  username varchar(120) NOT NULL UNIQUE ,
  password varchar(60) NOT NULL
);

CREATE INDEX idx_username_users
ON users(username);