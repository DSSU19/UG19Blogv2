const assert = require('assert');
const supertest = require('supertest');
const app = require('../server.js');
const nodemailer = require("nodemailer");
const sinon = require('sinon');
const crypto = require('crypto');
const fs = require('fs');
const request = supertest(app.app)

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


describe('getPasswordInfo',   function() {
    //Testing when the user inputs valid user data.
    it('User already exists in the system', async function() {
        const result = await app.getPasswordInfo('testuser2@gmail.com');
        assert.deepStrictEqual(result, {salt:'d5645ee6a22c2f3981fd80070a172ddf', pepper:'358727ccd1096f85ce3d2c958d958382'});
    });

    //Testing when the user inputs valid user data.
    it('User does not exists in the system', async function() {
        const result = await app.getPasswordInfo('invalidtestuser@gmail.com');
        assert.strictEqual(result, false);
    });
});


describe('validateLoginCredentials',   function() {
    //validUser
    const validUser = {
        email: 'wiwib28317@necktai.com',
        password: 'seates123',
    };

    const inValidUser = {
        email: 'lola@gmail.com',
        password: 'heyaa123',
    };

    //Testing when the user inputs valid user data.
    it('User does not exists in the system', async function() {
        const result = await app.validateLoginCredentials(validUser.password, validUser.email);
        assert.strictEqual(result, true);
    });
    it('User does not exists in the system', async function() {
        const result = await app.validateLoginCredentials(inValidUser.password, inValidUser.email);
        assert.strictEqual(result, false);
    });
});

/*
describe('loginPostRoute',   function() {
 //validUser
 const validUser = {
     email: 'wiwib28317@necktai.com',
     password: 'seates123',
 };

 const inValidUser = {
     email: 'lola@gmail.com',
     password: 'heyaa123',
 };

 it('Valid user login', done => {
     const callback = sinon.spy();
     sinon.replace(app, 'TwoFactorEmail', callback);
     request.post('/login')
         .send(validUser)
         .expect(200)
         .end((err) => {
             if (err) return done(err);
             done();
         });
 });

 it('Invalid login', done => {
     request.post('/login')
         .send(validUser)
         .expect.not(200)
         .expect('Content-Type', /html/)
         .end((err, res) => {
             if (err) return done(err);
             done();
         });
 });
});

 */
