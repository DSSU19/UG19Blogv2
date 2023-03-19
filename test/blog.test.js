const assert = require('assert');
const request = require('supertest');
const app = require('../server.js');

const { Pool } = require('pg');
const pool = new Pool({
    host: process.env.localhost,
    port: process.env.port,
    user: process.env.user,
    database: process.env.testDatabase,
    password:  process.env.password,
});


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
    // Clear the test database and insert a test user before running the tests
    before(function(done) {
        const deleteUserQuery = {
            text: 'DELETE FROM users',
        };

        pool.query(deleteUserQuery).then(()=>{
            const testUserData = { email: 'testemail@gmail.com', password: 'ce029hdg0a9d31de9576aa7c34c14fb30', verificationtoken: 'ce029hdg4d5632e9e70a9d31de9576aa7c34c14fb30', firstname: 'testUserName', creationTime: '1678781045009'};
            const insertTestUser = {
                text: 'INSERT INTO users (email, password, isverified, verificationtoken, firstname, creationTime) VALUES ($1, $2, $3, $4, $5, $6)',
                values: [testUserData.email, testUserData.password, true,testUserData.verificationtoken, testUserData.firstname, testUserData.creationTime  ] // 24 hours in milliseconds
            };
            pool.query(insertTestUser).then(()=>{
                console.log("User has been inserted")
                done()
            }).catch((err)=>{
                console.log("Insertion error is: "+ err)
                done()

            })

        }).catch((err)=>{
            console.log("This is the error"+ err)
            done(err)
        })


    });

    //User already exists in the database and has already sign-up
    it('Testing when the user already exists in the database ', function(done) {
        const res = {
            render: (view, data) => {
                assert.fail(`render() should not be called with view=${view} and data=${data}`);
            },
        };
        app.userExistsCheck('testemail@gmail.com', { render: function() {} },  function(exists) {
            assert.strictEqual(exists, true);
            done();
        });
    });

})






