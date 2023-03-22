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

describe('validateSearchInput', function() {
    //Testing when the user inputs valid user data.

    it('SQL Injection test', function() {
        const searchInput = '‘ order by username --'
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.searchBarValidation(searchInput);
        assert.strictEqual(result, false);
    });
    it('Correct Input', function() {
        const searchInput = 'Beyonce'
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.searchBarValidation(searchInput);
        assert.strictEqual(result, true);
    });

    it('SQL Injection test2', function() {
        const searchInput = '‘ or 1=1 --'
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.searchBarValidation(searchInput);
        assert.strictEqual(result, false);
    });

    it('SQL Injection test 3', function() {
        const searchInput = '\' union all select password from users --'
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.searchBarValidation(searchInput);
        assert.strictEqual(result, false);
    });

    it('SQL Injection test 4', function() {
        const searchInput = 'hrichard\' union all select name from \'users\' where username = \'hrichard\' –'
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.searchBarValidation(searchInput);
        assert.strictEqual(result, false);
    });

    it('Cross Site Request Attack', function() {
        const searchInput = '<script>alert("This is a pop-up");</script>'
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.searchBarValidation(searchInput);
        assert.strictEqual(result, false);
    });


    it('Escape Input: Cross Site Scripting', function() {
        const searchInput = '<script>alert("This is a pop-up");</script>'
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.escapeInput(searchInput)
        assert.notStrictEqual(searchInput,result)
    });




});



