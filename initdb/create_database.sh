#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$user" --dbname "$database" <<-EOSQL
    CREATE DATABASE blogDatabase;
    CREATE TYPE public.authmethod AS ENUM (
        'email',
        'totp'
    );
    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        isVerified BOOLEAN DEFAULT FALSE,
        verificationToken VARCHAR(255),
        firstName VARCHAR(255),
        creationTime BIGINT NOT NULL,
        authMethod public.authmethod NOT NULL
    );

    CREATE TABLE totp (
        email VARCHAR(255) PRIMARY KEY,
        secret VARCHAR(255),
        FOREIGN KEY (email) REFERENCES users(email)
    );

    CREATE TABLE otps (
        email VARCHAR(255),
        otp VARCHAR(255),
        used BOOLEAN,
        creationtime BIGINT,
        PRIMARY KEY (email, otp),
        FOREIGN KEY (email) REFERENCES users(email)
    );

    -- Create table for blogdata
    CREATE TABLE blogdata (
        id SERIAL PRIMARY KEY,
        blogtitle VARCHAR(255),
        bloginfo TEXT,
        datecreated TIMESTAMP,
        blogdescription VARCHAR(255),
        blogauthor VARCHAR(255),
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id)
);

EOSQL
