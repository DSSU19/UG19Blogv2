const assert = require('assert');
const supertest = require('supertest');
const app = require('../server.js');
const { expect } = require('chai');
const request = supertest(app.app);
const sinon = require('sinon');
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

async function deleteUserFromFile(email, saltFileName, pepperFileName){
    const saltData = await fs.promises.readFile(saltFileName, 'utf8');
    const saltObj = JSON.parse(saltData);
    const pepperData = await fs.promises.readFile(pepperFileName, 'utf8');
    const pepperObj = JSON.parse(pepperData);
    // Find the index of the object to remove
    const index = saltObj.user_info.findIndex((obj) => obj.email === email);
    const pepper_index = pepperObj.user_info.findIndex((obj) => obj.email === email);

    // Remove the object if it exists
    if (index !== -1 && pepper_index !== -1) {
        console.log('time to remove')
        saltObj.user_info.splice(index, 1);
        pepperObj.user_info.splice(index, 1);
    }
    // Write the updated file
    fs.writeFileSync(saltFileName, JSON.stringify(saltObj));
    fs.writeFileSync(pepperFileName, JSON.stringify(pepperObj));

}
describe('validateSignUpInputs', function() {
    //Testing when the user doesn't put anything in the username,  password, and email
    it('Testing when the user doesn\'t put anything in the username and password', function() {
        //should return an object with isValid equal to false and an array of errors when given invalid inputs
        const reqBody = {
            username: '',
            password: '', email: '',
            passwordConfirmation: ''
        };
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert(Array.isArray(result.errors));
        assert.strictEqual(result.errors.length, 4);
    });

    //Testing when the user inputs the correct format for the email, password, and username
    it('Testing when the user inputs valid data for all inputs', function() {
        //should return an object with isValid equal to true when given valid inputs
        const reqBody = {username: 'AbbyAmmo', password: 'seates123', email: 'abbyammo13@gmail.com', passwordConfirmation: 'seates123'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, true);
        assert.strictEqual(result.errors, undefined);
    });

    //Testing when the user inputs the incorrect email
    it('Testing invalid email', function() {
        //should return an object with isValid false to true when given invalid inputs
        const reqBody = {username: 'AbbyAmmo', password: 'seates123', passwordConfirmation: 'seates123', email: 'abbyammo13heates'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.equal(result.errors.length, 1);
    });

    //Testing when the user inputs the incorrect password length
    it('Testing incorrect password length', function() {
        //should return an object with isValid equal to false when given invalid inputs
        const reqBody = {username: 'AbbyAmmo', password: 'sell', passwordConfirmation: 'sell',email: 'abbyammo13@gmail.com'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.equal(result.errors.length, 1);
    });


    //Testing when the user inputs incorrect email
    it('Testing incorrect email ending', function() {
        //should return an object with isValid equal to true when given valid inputs
        const reqBody = {username: 'abbyAmmo', password: 'sell123@',passwordConfirmation: 'sell123@', email: 'abbyammo13@oushit.com'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, true);
        assert.equal(result.errors, undefined);
    });

    //Testing when the user inputs the incorrect username
    it('Testing invalid username', function() {
        //should return an object with isValid equal to false when given invalid inputs
        const reqBody = {username: '!@yubh', password: 'sell123@gety',passwordConfirmation: 'sell123@gety', email: 'abbyammo13@gmail.com'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.equal(result.errors.length, 1);
    });


    //Testing when the user places an invalid password confiramtion
    it('Testing when the user places an invalid password confiramtion', function() {
        //should return an object with isValid equal to true when given valid inputs
        const reqBody = {username: 'AbbyAmmo', password: 'seates123', email: 'abbyammo13@gmail.com', passwordConfirmation: 'seates12'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.strictEqual(result.errors.length, 1);
    });

    //Testing when the user places an invalid password confiramtion
    it('Basic SQL Injection Testing', function() {
        //should return an object with isValid equal to true when given valid inputs
        const reqBody = {username: "'", password: "'", email: "'", passwordConfirmation: "'"};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.strictEqual(result.errors.length, 3);
    });


    //Testing when the user inputs XSS Script attacks:
    it('Testing XSS Script Attack in inputs', function() {
        //should return an object with isValid equal to false when given invalid inputs
        const reqBody = {username: '<script>alert("HelloWorld"); </script>', password: 'sell123@gety', passwordConfirmation: 'sell123@gety', email: 'abbyammo13@gmail.com'};
        const result = app.signUpValidation(reqBody);
        assert.strictEqual(result.isValid, false);
        assert.equal(result.errors.length, 1);
    });

    it('Testing XSS Attack via email input vide', function() {
        const reqBody = {
            username: 'ABys',
            password: 'Hello, world!',
            passwordConfirmation: 'Hello, world!',
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
    //Might need this code for something else later!
   /*
    before(async function() {
       const deleteUserQuery = {
            text: 'DELETE FROM users',
        };
        await testPool.query(deleteUserQuery);

        const testUserData = { email: 'testemail@gmail.com', password: 'ce029hdg0a9d31de9576aa7c34c14fb30', verificationtoken: 'ce029hdg4d5632e9e70a9d31de9576aa7c34c14fb30', firstname: 'testUserName', creationTime: '1678781045009'};
        const insertTestUser = {
            text: 'INSERT INTO users (email, password, isverified, verificationtoken, firstname, creationTime) VALUES ($1, $2, $3, $4, $5, $6)',
            values: [testUserData.email, testUserData.password, true,testUserData.verificationtoken, testUserData.firstname, testUserData.creationTime  ] // 24 hours in milliseconds
        };
        await testPool.query(insertTestUser);
    });*/

    //User already exists in the database and has already sign-up
    it('Testing when the user already exists in the database ', async function() {
        const userExists = await app.userExistsCheck('wiwib28317@necktai.com');
        assert.strictEqual(userExists, true);
    });

    it('Testing when the user does not exists', async function() {
        const userExists = await app.userExistsCheck('abs145@necktai.com');
        assert.strictEqual(userExists, false);
    });

})

describe('passwordStore',  function () {
    //Create a salt and a pepper
    const salt = crypto.randomBytes(16).toString('hex');
    const pepper = crypto.randomBytes(16).toString('hex');
    const saltFileName = 'test/info/test_salt.json'
    const pepperFileName = 'test/info/test_pepper.json'
    const testSaltData = {
        email: 'testuser@gmail.com',
        salt: salt
    }
    const testPepper = {
        email: 'testuser@gmail.com',
        pepper: pepper
    }
    before(async function () {
        await deleteUserFromFile(testSaltData.email, saltFileName, pepperFileName)
        // runs before all tests in this file regardless where this line is defined
    });
    //Testing the password store function, should return true
    it('Testing salt and pepper storage ', async function () {
        const saltResult = await app.storePasswordInfo(saltFileName, testSaltData)
        assert.strictEqual(saltResult, true)
        const pepperResult = await app.storePasswordInfo(pepperFileName, testPepper)
        assert.strictEqual(pepperResult, true)
    });


    //Testing the password store function, should return true
    it('Testing salt and pepper duplicates', async function () {
        //Testing with user
        const salt = crypto.randomBytes(16).toString('hex');
        const pepper = crypto.randomBytes(16).toString('hex');
        const saltResult = await app.storePasswordInfo(saltFileName, testSaltData)
        assert.strictEqual(saltResult, false)
        const pepperResult = await app.storePasswordInfo(pepperFileName, testPepper)
        assert.strictEqual(pepperResult, false)
    });
})





describe('Sign up full functionality', () => {
    let csrfTokenValue = '7f5c21a7d98f9a47857289d89a63fd8d98cd4fbe50f25906b910f1350f5a91b0';
    let email = 'wiwib28317@necktai.com'
    before(async function() {
        const saltFileName= 'test/info/test_salt.json'
        const pepperFileName= 'test/info/test_pepper.json'
        await deleteUserFromFile(email, saltFileName, pepperFileName)
        const deleteUserQuery = {
            text: 'DELETE FROM users WHERE email = $1',
            values: [email]
        };
        await testPool.query(deleteUserQuery).then(console.log('done'));
    })
    it('Valid user sign-up', done => {
        request
            .post('/sign-up')
            .send(
                {
                    email: email,
                    password: 'seates123',
                    passwordConfirmation: 'seates123',
                    username: 'testuser',
                    csrftokenvalue: csrfTokenValue, // Include the CSRF token in the request body
                    authmethod: 'totp',
                }
            )
            .expect(200)
            .expect('Content-Type', /html/)
        // Check that the email and csrfToken values were passed to the view
            .end((err, res, req) => {
                console.log(res.text)
                expect(res.text).to.contain('Email Verficiation Token')
                if (err) return done(err);
                //assert.strictEqual(app.signUpValidation(testUserData).isValid, true);
                done();
            });
    });
});




