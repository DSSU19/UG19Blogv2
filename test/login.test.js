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
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const reqBody = {email: 'abbyammo13@gmail.com', password: 'seates123'};
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, true);
    });

    //Testing when the user inputs valid user data.
    it('Testing when the user inputs valid data', function() {
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const reqBody = {email: '', password: ''};
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, false);
    });

    //Testing when the user inputs valid user data.
    it('Testing when the user inputs valid data', function() {
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const reqBody = {email: '', password: ''};
        const result = app.loginValidation(reqBody);
        assert.strictEqual(result, false);
    });

});






