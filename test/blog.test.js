const assert = require('assert');
const request = require('supertest');
const app = require('../server.js');


describe('validateInputs', function() {
    //Testing when the user doesn't put anything in the username,  password, and email
    it('Testing when the user doesn\'t put anything in the username and password', function() {
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const reqBody = {username: '', password: '', email: ''};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert(Array.isArray(result.errors));
        assert.strictEqual(result.errors.length, 3);
    });

    //Testing when the user inputs the correct format for the email, password, and username
    it('Testing when the user inputs the correct format for the email, password, and username', function() {
        //should return an object with isValid equal to true when given valid inputs
        const reqBody = {username: 'AbbyAmmo', password: 'seates123', email: 'abbyammo13@gmail.com'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, true);
        assert.strictEqual(result.errors, undefined);
    });

    //Testing when the user inputs the incorrect email
    it('Testing incorrect email', function() {
        //should return an object with isValid false to true when given invalid inputs
        const reqBody = {username: 'AbbyAmmo', password: 'seates123', email: 'abbyammo13heates'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.equal(result.errors.length, 1);
    });

    //Testing when the user inputs the incorrect password length
    it('Testing incorrect password length', function() {
        //should return an object with isValid equal to false when given invalid inputs
        const reqBody = {username: 'AbbyAmmo', password: 'sell', email: 'abbyammo13@gmail.com'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.equal(result.errors.length, 1);
    });


    //Testing when the user inputs incorrect email
    it('Testing incorrect email ending', function() {
        //should return an object with isValid equal to true when given valid inputs
        const reqBody = {username: 'abbyAmmo', password: 'sell123@', email: 'abbyammo13@oushit.com'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, true);
        assert.equal(result.errors, undefined);
    });

    //Testing when the user inputs the incorrect username
    it('Testing invalid username', function() {
        //should return an object with isValid equal to false when given invalid inputs
        const reqBody = {username: '!@yubh', password: 'sell123@gety', email: 'abbyammo13@gmail.com'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.equal(result.errors.length, 1);
    });

    //Testing when the user inputs XSS Script attacks:
    it('Testing XSS Script Attack in inputs', function() {
        //should return an object with isValid equal to false when given invalid inputs
        const reqBody = {username: '<script>alert("HelloWorld"); </script>', password: 'sell123@gety', email: 'abbyammo13@gmail.com'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.equal(result.errors.length, 1);
    });

    it('Testing XSS Attack via email input vide', function() {
        const reqBody = {
            username: 'ABys',
            password: 'Hello, world!',
            email: '<img src="image.jpg">@gmail.com'
        };
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.equal(result.errors.length, 1);
    });


});


describe('escapeInput', function(){
    //Testing with no values that needs to be escaped
    it('Testing with no values that needs to be escaped', function() {
        //should return the same json object
        const reqBody = {username: 'AbbyAmmo', password: 'sell1234', email: 'abbyammo13@gmail.com'};
        const result = app.escapeAllInput(reqBody);
        const expectedOutput = {username: 'AbbyAmmo', password: 'sell1234', email: 'abbyammo13@gmail.com'}
        assert.deepEqual(result, expectedOutput);
    });

    //Testing with some values that needs to be escaped:
    it('Testing with a values that needs to be escaped', function() {
        const reqBody = {
            username: '<script>alert("HelloWorld");</script>',
            password: 'sell1234',
            email: 'abbyammo13@gmail.com'
        };
        const result = app.escapeAllInput(reqBody);
        const expectedOutput = {
            username: "&lt;script&gt;alert(&quot;HelloWorld&quot;);&lt;&#x2F;script&gt;",
            password: 'sell1234',
            email: 'abbyammo13@gmail.com'
        };
        assert.deepEqual(result, expectedOutput);
    });

    it('Testing with multiple values that needs to be escaped', function() {
        const reqBody = {
            username: '<script>alert("HelloWorld");</script>',
            password: 'sell1234',
            email: '<img src="image.jpg">'
        };
        const result = app.escapeAllInput(reqBody);
        const expectedOutput = {
            username: "&lt;script&gt;alert(&quot;HelloWorld&quot;);&lt;&#x2F;script&gt;",
            password: 'sell1234',
            email: '&lt;img src=&quot;image.jpg&quot;&gt;'
        };
        assert.deepEqual(result, expectedOutput);
    });
})

describe('userAlreadyExists', function(){
    //User already exists in the database and has already sign-up
    it('User exists in the database and has already sign-up', function() {

    });

})






