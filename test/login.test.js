const assert = require('assert');
const supertest = require('supertest');
const app = require('../server.js');
const nodemailer = require("nodemailer");
const sinon = require('sinon');
const crypto = require('crypto');
const fs = require('fs');
const speakeasy = require("speakeasy");
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
async function deleteUserFromFile(email, fileName){
    const fileDta = await fs.promises.readFile(fileName, 'utf8');
    const userObj = JSON.parse(fileDta);
    // Find the index of the object to remove
    const index = userObj.user_info.findIndex((obj) => obj.email === email);
    // Remove the object if it exists
    if (index !== -1) {
        console.log('time to remove')
        userObj.user_info.splice(index, 1);
    }
    // Write the updated file
    fs.writeFileSync(fileName, JSON.stringify(userObj));
}
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


//These methods are for the encryption of the key before database storage
describe('encryptionMethod', function(){
    const secret = 'my_secret_key';
    const email= 'abbyammo13@gmail.com'
    //Testing when the user inputs valid user data.
    it('Email is not duplicated', async function() {
        const result = await app.encryptWord(secret, email);
        assert.notStrictEqual(result, false);
    });
    it('email encryption key has already been stored in json', async function() {
        const result = await app.encryptWord(secret, email);
        assert.strictEqual(result, false);
    });

})

//This method is for the decryption of the secret to be used for 2FA totp login
describe('decryptionMethod', function(){
    const email= 'abbyammo13@gmail.com'
    const notStoredEmail= 'abbyammo14@gmail.com'
    const decryptionTestEmail= 'abbyammo14@gmail.com'
    const secret = 'my_secret_key';
    let speakeasySecret =    speakeasy.generateSecret({ length: 20 });
    speakeasySecret= speakeasySecret.base32;

    const keyFileName = process.env.NODE_ENV === "test" ? 'test/info/test_keys.json': 'info/keys.json';
    before(async function() {
        await deleteUserFromFile(decryptionTestEmail, keyFileName);
        // runs before all tests in this file regardless where this line is defined
    });
    //Testing when the user inputs valid user data.
    it('get keys method functionality_ email exists', async function() {
        const result = await app.getEncryptionKeys(email, keyFileName) ;
        assert.notStrictEqual(result, false);
    });
    it('Get keys, user not stored', async function() {
        const result = await app.getEncryptionKeys(notStoredEmail, keyFileName) ;
        assert.strictEqual(result, false);
    });


    it('Decryption method', async function() {
        const encryptedWord = await app.encryptTotpInfo(secret, decryptionTestEmail)
        const result = await app.decryptTotpInfo(encryptedWord, decryptionTestEmail) ;
        assert.notStrictEqual(result, false);
        assert.strictEqual(result, secret);
    });

    it('Decryption method on speakeasy secret', async function() {
        const encryptedWord = await app.encryptTotpInfo(speakeasySecret, decryptionTestEmail)
        const result = await app.decryptTotpInfo(encryptedWord, decryptionTestEmail) ;
        assert.notStrictEqual(result, false);
        assert.strictEqual(result, speakeasySecret);
    });




})

describe('resetPassword', function(){

    //Create a salt and a pepper
    const salt =  crypto.randomBytes(16).toString('hex');
    const pepper = crypto.randomBytes(16).toString('hex');
    let testPasswordData = {
        email: 'wiwib28317@necktai.com',
        pepper: pepper,
        salt: salt,
        newPassword: 'destinyIsCallingMyName'
    }
    it('Testing update user info function', async function(){
        const updateInfoFunctionResult = await app.updatePasswordInfo(testPasswordData)
        assert.strictEqual(updateInfoFunctionResult, true);



    })
    it('Rehashing new password test', async function(){
        let result = await app.reHashNewPassword(testPasswordData)
        assert.notStrictEqual(result, false)
    })
})

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
