DROP DATABASE IF EXISTS bserv;
CREATE DATABASE bserv;
\connect bserv

CREATE TABLE auth_user (
    id serial PRIMARY KEY,
    username character varying(255) NOT NULL UNIQUE,
    password character varying(255) NOT NULL,
    is_superuser boolean NOT NULL,
    first_name character varying(255) NOT NULL,
    last_name character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    is_active boolean NOT NULL,
    is_musician int DEFAULT 0 NOT NULL
);
CREATE TABLE music (
    music_id serial PRIMARY KEY,
    musician_id int references auth_user(id),
    music_name character varying(255) NOT NULL,
    music_path character varying(255) NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);
CREATE TABLE comment (
    comment_id serial PRIMARY KEY,
    user_id int references auth_user(id) NOT NULL,
    music_id int references music(music_id) NOT NULL,
    comment_time timestamp NOT NULL,
    comment_content character varying(1023)
);
CREATE TABLE favorite (
    user_id int references auth_user(id),
    music_id int references music(music_id),
    create_time timestamp NOT NULL,
    PRIMARY KEY(user_id, music_id)
);

insert into "auth_user" ("username", password, is_superuser, first_name, last_name, email, is_active) values ('superuser', 'KZfaabUkFFUZLArn$w5XUUH3i2eohBk26uvvUujjPtzo9yV1hNeCVp/P5k64=', true, '', '', '', true);