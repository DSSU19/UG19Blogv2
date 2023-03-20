const assert = require('assert');
const request = require('supertest');
const app = require('../server.js');
const nodemailer = require("nodemailer");
const crypto = require('crypto');
const fs = require('fs');

const { Pool } = require('pg');
const testPool = new Pool({
    host: process.env.localhost,
    port: process.env.port,
    user: process.env.user,
    database: process.env.testDatabase,
    password:  process.env.password,
});

/*Make sure yoy copy and paste the code below if you are
running tests that have to deal with queries update, insert, delete.
 */

//NODE_ENV=test mocha

describe('validateLoginInput', function() {
    //Testing when the user inputs valid user data.
    it('Testing when the user inputs valid data', function() {
        const reqBody = {email: 'abbyammo13@gmail.com', password: 'seates123'};
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, true);
    });

    //Testing when the user inputs valid user data.
    it('Testing when the user inputs valid data', function() {
        const reqBody = {email: '', password: ''};
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, false);
    });

    it('Testing against XSS Attacks ', function() {
        const reqBody = {  email: '<script>alert("Hello World");</script>', password:'<script>alert("Hello World");</script>' };
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, false);
    });


    it('Single quote SQL Injection test', function() {
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const reqBody = {  email: "'", password:"'" };
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, false);
    });

    it(' SQL Injection \'or "=" test', function() {
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const reqBody = {  email: "' or \"=\"", password:"' or \"=\"" };
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, false);
    });

    it(' SQL Injection \' or 1-- test ', function() {
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const reqBody = {  email: "' or 1--", password:"" };
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, false);
    });

    //Incorrect password length check
    it('Testing Incorrect password length', function() {
        const reqBody = {email: 'abbyammo13@gmail.com', password: 'h@4f'};
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, false);
    });

    //Incorrect password length check
    it('Testing Incorrect email input', function() {
        const reqBody = {email: 'a123.com', password: 'seates123@'};
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, false);
    });


});






