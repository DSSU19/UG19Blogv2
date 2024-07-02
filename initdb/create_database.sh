#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$user" --dbname "$database" <<-EOSQL
    CREATE TYPE public.authmethod AS ENUM (
        'email',
        'totp'
    );
    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        isVerified BOOLEAN DEFAULT FALSE,
        verificationToken VARCHAR(255),
        firstName VARCHAR(255),
        creationTime BIGINT NOT NULL,
        authMethod public.authmethod NOT NULL
    );

    CREATE TABLE otps (
        id BIGSERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        otp VARCHAR(255) NOT NULL,
        secret VARCHAR(255) NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        creationTime TIMESTAMP NOT NULL
    );

    CREATE TABLE blogdata (
        id BIGSERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        blogTitle VARCHAR(255) NOT NULL,
        blogInfo TEXT,
        blogDescription TEXT,
        blogAuthor VARCHAR(255),
        user_id INT NOT NULL,
        FOREIGN KEY (email) REFERENCES users(email),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    ALTER TABLE otps ADD CONSTRAINT fk_otp_email FOREIGN KEY (email) REFERENCES users(email);
EOSQL
