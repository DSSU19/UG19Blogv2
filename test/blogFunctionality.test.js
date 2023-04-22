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
    it('Add Blog Posts SQL Injection', function() {
        const blogData={
            blogTitle: '‘ order by username --',
            blogDescription: "'‘ order by username --'",
            blogData: "There is an invalid input in your blog dataa",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.blogFormDataValidation(blogData);
        assert.strictEqual(result.isValid, false);
        assert.strictEqual(result.errors.length, 2);


    });

    it('Add Blog Posts SQL Injection 2', function() {
        const blogData={
            blogTitle: ' \' union all select name from users --',
            blogDescription: "'‘ order by username --'",
            blogData: "There is an invalid input in your blog dataa",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.blogFormDataValidation(blogData);
        assert.strictEqual(result.isValid, false);
        assert.strictEqual(result.errors.length, 2);

    });

    it('Add Blog Posts SQL Injection 3', function() {
        const blogData={
            blogTitle: ' \' union all select name from users --',
            blogDescription: "'‘ order by username --'",
            blogData: "hrichard' union all select name from 'users' where username = 'hrichard' –",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.blogFormDataValidation(blogData);
        assert.strictEqual(result.isValid, false);
        assert.strictEqual(result.errors.length, 3);

    });

    it('Cross Site Scripting', function() {
        const blogData={
            blogTitle:  '<script>alert("Hello World");</script>',
            blogDescription: '<script>alert("Hello World");</script>',
            blogData: "Javascript is changing the world. ",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.blogFormDataValidation(blogData);
        assert.strictEqual(result.isValid, false);
        assert.strictEqual(result.errors.length, 2);

    });

    it('Accurate Input Test', function() {
        const blogData={
            blogTitle:  "Everyone needs a dog",
            blogDescription: "Doggies need a little love to",
            blogData: "We love dog, we love dogs, everyday is a dog loving day!!! ",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.blogFormDataValidation(blogData);
        assert.strictEqual(result.isValid, true);
        assert.strictEqual(result.errors.length, 0);

    });



    it('Accurate Input Test', function() {
        const blogData={
            blogTitle:  "Everyone needs a dog",
            blogDescription: "Doggies need a little love to",
            blogData: "We love dog, we love dogs, everyday is a dog loving day!!! ",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.validateInputsAll(blogData);
        assert.strictEqual(result.isValid, true);
        assert.strictEqual(result.errors.length, 0);

    });


    it('Cross Site Scripting', function() {
        const blogData={
            blogTitle:  '<script>alert("Hello World");</script>',
            blogDescription: '<script>alert("Hello World");</script>',
            blogData: "Javascript is changing the world. ",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.blogFormDataValidation(blogData);
        assert.strictEqual(result.isValid, false);
        assert.strictEqual(result.errors.length, 2);

    });

    it('Valid Inputs', function() {
        const blogData={
            blogTitle:  "Everyone needs a dog",
            blogDescription: "Doggies need a little love to",
            blogData: "We love dog, we love dogs, everyday is a dog loving day!!!",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.validateInput(blogData);
        assert.strictEqual(result.isValid, true);
        assert.strictEqual(result.errors, undefined);

    });

    it('Valid Inputs 2', function() {
        const blogData={
            blogTitle:  "Everyone needs a dog 2gh",
            blogDescription: "Doggies need a little love to ghana",
            blogData: "We love dog, we love dogs, everyday is a dog loving day!!! hello",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.validateInput(blogData);
        assert.strictEqual(result.isValid, true);
        assert.strictEqual(result.errors, undefined);

    });


    it('Encrypt word', function() {
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const unencryptedWord = "seates123"
        const result = app.encryptWord(unencryptedWord);
        assert.notStrictEqual(result, unencryptedWord);
    });

    it('Decrypt word', function() {
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const unencryptedWord = "seates123"
        const encryptedWordObject = app.encryptWord(unencryptedWord);
        const result = app.decryptWord(encryptedWordObject)
        assert.strictEqual(result, unencryptedWord)
    });

    it('Output character Encoding', function() {
        const blogData={
            blogTitle: '‘ order by username --',
            blogDescription: "'‘ order by username --'",
            blogData: "There is an invalid input in your blog dataa",
        }
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const result = app.blogFormDataValidation(blogData);
        assert.strictEqual(result.isValid, false);
        assert.strictEqual(result.errors.length, 2);


    });



});



