const express = require('express');
require('dotenv').config({path:'info.env'});
const https = require('https');
const bodyParser = require('body-parser');
const nodemailer = require("nodemailer");
const fs = require('fs');
const ejs = require('ejs');
const crypto = require('crypto');
const argon2 = require('argon2');
const helmet = require('helmet');

const speakeasy = require('speakeasy');
const qrCode = require('qrcode');
const session = require('express-session');
const cookieParser = require('cookie-parser');//Cookie parser being used for the double submit cookie value.
const { v4: uuid } = require('uuid')
//import rateLimiter from 'express-rate-limit'

const rateLimiter = require('express-rate-limit');
const axios = require('axios');
const app = express();

// Middleware and server set up
app.use(bodyParser.urlencoded({ extended: false }));
app.set('view engine', 'ejs');
app.set('views', 'views');
const port = 8080;
//Pg client information to enable queries from the database blog.
const { Pool } = require('pg');
//Switches the database name based on whether we are testing or using the actual application
const databaseName = process.env.NODE_ENV === "test" ? process.env.testDatabase : process.env.database;

const pool = new Pool({
    host: process.env.localhost,
    port: process.env.port,
    user: process.env.user,
    database: databaseName,
    password:  process.env.password,
});

const readOnlyPool = new Pool({
    host: process.env.localhost,
    port: process.env.port,
    user: process.env.readOnlyUser,
    database: databaseName,
    password:  process.env.readOnlyUserPassword,
});

const writeOnlyPool = new Pool({
    host: process.env.localhost,
    port: process.env.port,
    user: process.env.writeOnlyUser,
    database: databaseName,
    password:  process.env.writeOnlyUserPassword,
});

//This includes security headers such as Content-Security-Policy, X-Content-Type-Options, X-XSS-Protection, X-Frame-Options, Strict-Transport-Security
//This sets several secure https headers, this is known for preventing Cross Site Scripting and click-jacking attacks
// Sets all of the defaults, but overrides `script-src` and disables the default `style-src`


//To ensure that this works with the google captcha as according to their documentation: https://developers.google.com/recaptcha/docs/faq
const nonce = crypto.randomBytes(16).toString('base64'); //A nonce needs to be generated

app.use(
    helmet.contentSecurityPolicy({
        directives: {
            "script-src": ["'self'", "https://www.google.com/recaptcha/", "https://www.gstatic.com/recaptcha/", `'nonce-${nonce}'`],// This is to allow google captcha scripts to be loaded
            "frame-src": ["https://www.google.com/recaptcha/", " https://recaptcha.google.com/recaptcha/", `'nonce-${nonce}'`] //This is to enable the google captcha scripts to be loaded by the CSP


        },
    })
);

app.use(express.static('client'));
//Use the cookie parser for the double submit cookie.
app.use(cookieParser(process.env.cookie_secret_key));
//app.use(cookieParser());






// Body parser middleware
app.use(bodyParser.json());
//Force input to be encoded correctly.
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.secret_key,
    name: 'sessionId',
    genid : function (req){
        const sessionID = crypto.randomBytes(16).toString('hex');
        const encryptionKey = crypto.randomBytes(32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
        let encryptedSessionID = cipher.update(sessionID, 'utf8', 'hex') + cipher.final('hex');
        return encryptedSessionID
        //return  crypto.randomBytes(16).toString('hex');
    },
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: true,
        httpOnly:true,
        expires:  5 * 60 * 60 * 1000, //Cookies expire after 5 hours, in order to prevent session hijacking
        sameSite: 'strict',
    }
}));

app.use((req, res, next) => {
    //console.log(req.session.csrfToken)
    //console.log(req.session.csrfToken || Date.now() > req.session.csrfTokenExpiry)
    if(process.env.NODE_ENV==="test"){
        const tenMinutesTimer = 1000*60*10
        req.session.csrfToken = process.env.test_csrf_token;
        req.session.csrfTokenExpiry = Date.now() + tenMinutesTimer;
    }
    if(req.url==="/logout"){
        return next()
    }else if (!req.session.csrfToken||  Date.now() > req.session.csrfTokenExpiry){
        console.log("This gets run")
        req.session.csrfToken = crypto.createHmac('sha256', process.env.token_secret_key).update(crypto.randomBytes(32).toString('hex')).digest('hex');
        //console.log(encryptWord(req.session.csrfToken))
        //const thirtyMinutesTimer = 1800000
        //const twoMinutesTimer = 120000 //Two minutes for testing
        const fortyFiveMinutesTimer = 1000*60*45
        req.session.csrfTokenExpiry = Date.now() + fortyFiveMinutesTimer;
    }
    if (req.method==="POST" && (!req.body['csrftokenvalue'] || req.body['csrftokenvalue'] !== req.session.csrfToken )){
        console.log('Post Data: ' + "csrf body value:" +  req.body['csrftokenvalue'] + " SESSION: " + req.session.csrfToken)
        return res.status(403).end();
    }
    next();
});



app.use('/addBlogPost', (req,res,next)=>{
    //console.log(req.session.csrfToken || Date.now() > req.session.csrfTokenExpiry)
    if(req.url==="/logout"){
        return next()
    }else if (!req.session.doubleSubmitCookie||  Date.now() > req.session.doubleSubmitCookieTokenExpiry){
        req.session.doubleSubmitCookie = crypto.createHmac('sha256', process.env.token_secret_key).update(crypto.randomBytes(32).toString('hex')).digest('hex');
        // Store the CSRF token in a cookie.
        res.cookie('doubleSubmitCookie', req.session.doubleSubmitCookie,{
            secure: 'true', //cookie can only be transmitted over https as OWASP reccomended
            httpOnly: true, //prevents client side script from accessing the cookie
            sameSite: 'strict',// prevents cookie from being sent in cross site requests
            maxAge:  5 * 60 * 60 * 1000, //Cookies expire after 5 hours, in order to prevent session hijacking
            signed: true, //signs the cookie to prevent the cookie from being tampered for additional security
        });
        //const twoMinutesTimer = 120000 //Two minutes for testing
        const fortyFiveMinutesTimer = 1000*60*45
        req.session.doubleSubmitCookieTokenExpiry = Date.now() + fortyFiveMinutesTimer;
    }
    if (req.method==="POST" && (!req.body['doubleSubmitCookie'] || req.body['doubleSubmitCookie'] !== req.signedCookies.doubleSubmitCookie )){
        console.log('Double Submit Cookie Post ' + req.body['doubleSubmitCookie'], req.session.doubleSubmitCookie)
        return res.status(403).end();
    }
    next();
})


app.use('/login', (req,res,next)=>{
    if(req.session){
        //Check if the user has been able to successfully login
        //console.log('session-based-rate limiting be implemented')
        if(!req.session.usermail){
            const now = new Date();
                if(!req.session.loginAttempts){
                    req.session.loginAttempts = 1
                }else{
                    req.session.loginAttempts +=1;
                }
            if(req.session.loginAttempts > 5){
                console.log('You have too  many login attempts')
                // Check if the last login attempt was more than an hour ago
                const lastAttempt = new Date(req.session.lastLoginAttempt || 0);
                const elapsed = now - lastAttempt;
                const fiveMinuteTester = 1000*60*5
                const fifteenMinuteTimer= 15 * 60 * 1000
                if (elapsed <fifteenMinuteTimer ) {
                    const remainingTime = fifteenMinuteTimer - elapsed;
                    const remainingMinutes = Math.ceil(remainingTime / 60000);
                    res.render('index', {
                        errors: `Too many login attempts. Please try again after ${remainingMinutes} minute(s).`,
                        message: false, csrfToken: req.session.csrfToken
                    })
                    return;
                }
                if (elapsed >= fifteenMinuteTimer) {
                    // Reset loginAttempts count
                    req.session.loginAttempts = 0;
                }

            }
            req.session.lastLoginAttempt = now.getTime();
            console.log("Login Attempts: "+  req.session.loginAttempts)
            //Increase number of login attempts count
        }
    }
    next()
})

/*app.use((req,res, next)=>{
    if(req.session.passwordResetTimeCreationDate){

    }
})*/



//This is to prevent a DDOS Attack
const limiter = rateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    message: "Too many request is being made from this IP, please try again later",
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})

app.use(limiter)

const loginLimiter = rateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // Limit each IP to 5 login requests per `window` (here, per hour)
    message:
        'Too many login attempts from this IP in the past hour, please try again after an hour',
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers

})

//Check if there is an active session
let inActivityTimer = 0
let userTimedOut = false;
let thirtyMinuteTimer = 30* 60*1000
//Reset the inactivity timer whenever the user makes a request (interacts with the websites)
app.use((req,res, next)=>{
    //If the user interacts with the website
    if(req.session.usermail || req.session.verifiedTotpUserEmail || req.session.totpLoginUserMail){
        //console.log('I am in here')
        //Stop the timer
        clearTimeout(inActivityTimer)
        //Reset the timer again
        inActivityTimer = setTimeout(() => {
            req.session.destroy((err)=>{
                if(err){
                    console.log(err)
                }else{
                    userTimedOut = true
                    console.log('Session destroyed due to inactivity.');
                }
            });
        }, 30*60*1000); // 2 minutes for testing, 30 minutes for actual implmentation.
    }
    next()
})

/*app.use(async(req,res,next)=>{
    let tokenSessionTime= req.session.passwordResetTimeCreationDate
    if(tokenSessionTime){
        let currentTime = Date.now()
        const fiveMinuteTimer = 1000*60*5
        if(currentTime > tokenSessionTime + fiveMinuteTimer){
            // This query resets
            const resetPassword={
                text: 'UPDATE users SET passwordReset = $1 WHERE email = $2 ',
                values: [null, req.session.resetEmail]
            }
            let deletePasswordToken = await writeOnlyPool.query(resetPassword)
            if(deletePasswordToken){
                console.log('delete the password reset token')
                delete req.session.resetEmail;
            }
        }

    }
    next()
})*/



//Transporter for sending emails:
// create reusable transporter object using the default SMTP transport
let transporter = nodemailer.createTransport({
    host: process.env.email_host,
    port: process.env.email_port,
    secure: process.env.email_secure, // true for 465, false for other ports
    auth: {
        user: process.env.email_user, // generated ethereal user. In production environment, this will be outsourced to a different server.
        pass: process.env.email_pass, // generated ethereal password
    },
});


//This is to get the server running
const options = {
    key: fs.readFileSync('mydomain.local+3-key.pem'),
    cert: fs.readFileSync('mydomain.local+3.pem')
};
const server = https.createServer(options, app);
server.listen(port, () => {
    console.log('Server running at https://localhost:8080/');
});



module.exports = {
    app,signUpValidation, escapeAllInput, userExistsCheck, storePasswordInfo,loginValidation, getPasswordInfo, validateLoginCredentials, searchBarValidation, escapeInput,
    blogFormDataValidation, validateInputsAll, validateInput,  encryptTotpInfo, getEncryptionKeys, decryptTotpInfo, encryptWord, decryptWord, limiter, updatePasswordInfo, reHashNewPassword
};
/*All functions used*/


/*Functions for the sign up functionality*/
function signUpValidation(reqBody){
    const errorMessages = {
        username: "Username must be alphanumeric",
        password: "Password must be at least 8 characters long",
        email: "Please enter a valid email address",
        passwordConfirmation: "Passwords do not match.",
        authmethod:'There is something wrong with your authMethod',
        csrftokenvalue: 'Unauthorised post request',
        location: 'You are a bot! No entry for you.'

    };
    const errors = [];
    const passwordRegex = /(?=.{8,}$)(?=.*[a-zA-Z0-9]).*/
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const usernameRegex= /^[a-z0-9]+$/i;
    for (const inputName in reqBody) {
        const input = reqBody[inputName];

       if(
            (inputName==="location" &&input)
            ||(!input && inputName!=="location")
            ||(input.length < 1 && inputName!=="location")
            ||(inputName==="username" && !usernameRegex.test(input))
            ||(inputName==="password" && !passwordRegex.test(input))
            || (inputName ==="email" && !emailRegex.test(input))
            || ((inputName==="passwordConfirmation") && input !== reqBody["password"])
            || ((inputName==="authmethod") && (input!=="email") && (input!=="totp"))
            || ((inputName==="csrftokenvalue")&& !usernameRegex.test(input)) || input===undefined
        ){
            errors.push(errorMessages[inputName]);
            console.log(errorMessages[inputName]);
        }
    }
    if (errors.length > 0) {
        console.log('Error')
        return { isValid: false, errors };
    } else {
        return { isValid: true };
    }
}

//Function to prevent XSS attacks
function escapeAllInput(reqBody){
    const escapeChars = {
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&#39;',
        '/': '&#x2F;'
    };
    const regex = /[<>&"'/]/g;
    for (const inputName in reqBody){
        reqBody[inputName]  = reqBody[inputName].replace(regex, (match) => escapeChars[match] )
    }
    //console.log("This is the escaped version" + JSON.stringify(reqBody));
    return reqBody
}

function escapeInput(input) {
    const escapeChars = {
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&#39;',
        '/': '&#x2F;'
    };
    const regex = /[<>&"'/]/g;
    return input.replace(regex, (match) => escapeChars[match]);
}

//function to check if the  user already exists (must be a verified user)
 function userExistsCheck(email){
    return new Promise((resolve, reject) => {
        //console.log('Exists function is executed');
        const userSelectQuery = {
            text: 'SELECT * FROM users WHERE email = $1',
            values: [email] // 24 hours in milliseconds
        };
        //need to have a handle on when the user has signed up but isn't verified.
        readOnlyPool.query(userSelectQuery)
            .then((result) => {
                //console.log(result.rows[0])
                if (result.rows.length > 0) {
                    console.log("User exists");
                    resolve(true);
                } else {
                    console.log("User does not exist");
                    resolve(false);
                }
            })
            .catch((err) => {
                console.log("\The error is:" + err)
            });
    });
}

//function store the password salt and pepper information
async function storePasswordInfo(filename, passwordData) {
    try {
        const data = await fs.promises.readFile(filename, 'utf8');
        const obj = JSON.parse(data);
        const userStorageCheck = obj.user_info.find(u => u.email === passwordData.email);
        if (!userStorageCheck) {
            //console.log("user does not exist");
            obj.user_info.push(passwordData);
            const user_json = JSON.stringify(obj, null, 4);
            await fs.promises.writeFile(filename, user_json, 'utf8');
            console.log('Saved!');
            return true;
        } else {
            return false;
        }
    } catch (err) {
        if (err.code === 'ENOENT') {
            console.log('File does not exist. Creating new file...');
            const user_data = {user_info: [passwordData]};
            const user_json_stringify = JSON.stringify(user_data, null, 4);
            await fs.promises.writeFile(filename, user_json_stringify, 'utf8');
           // console.log('Data saved successfully!');
            return true;
        } else {
            console.log(err);
            return false;
        }
    }
}
async function updatePasswordInfo(passwordData){
    //console.log('it gets here')
    const pepperFileName = process.env.NODE_ENV === "test" ? './test/info/test_pepper.json': './info/pepper.json';
    const saltFileName = process.env.NODE_ENV === "test" ? './test/info/test_salt.json': './info/salts.json';
    try{
        const saltFile = await fs.readFileSync(saltFileName);
        const saltObj = JSON.parse(saltFile);
        const saltUserValue = saltObj.user_info.find(user => user.email === passwordData.email);
        const pepperFile = await fs.readFileSync(pepperFileName);
        const pepperObj = JSON.parse(pepperFile);
        const pepperUserValue = pepperObj.user_info.find(user => user.email === passwordData.email);
        if (!saltUserValue || !pepperUserValue) {
            return false;
        }else{
            // update the salt value for the user
            //console.log('Json object value: ' +JSON.stringify(saltUserValue))
            //console.log('SALT AND PEPPER: ' + passwordData.salt, passwordData.pepper)
            saltUserValue.salt = passwordData.salt
            pepperUserValue.pepper = passwordData.pepper
            //console.log("New salt: " + JSON.stringify(saltObj))
            //console.log("New Pepper: " + JSON.stringify(pepperObj))
            // write the updated data back to the JSON file
             fs.writeFile(saltFileName, JSON.stringify(saltObj, null, 4), (err) => {
                if (err) throw err;
                //console.log(`Salt updated for user with email ${passwordData.email}`);
            });
            fs.writeFile(pepperFileName, JSON.stringify(pepperObj, null, 4), (err) => {
                //console.log(`Salt updated for user with email ${passwordData.email}`);
                if (err) return false;
            });
            return true
        }
    }catch(err){
        console.log(err)

    }
}

async function reHashNewPassword(passwordData){
    let updateSaltAndPepper = await updatePasswordInfo(passwordData)
    let {newPassword, salt, pepper} = passwordData
    console.log(newPassword)
    if(updateSaltAndPepper){
        const hashedPassword = await argon2.hash(
            newPassword + pepper, // Combine the new password and pepper
            {
                type: argon2.argon2id, // Uses the Argon2id algorithm as reccommended by the OWASP cheat sheet website
                salt: Buffer.from(salt, 'hex'), // This converts the salt to a buffer
                timeCost: 4, // 4 passe//  ()
                hashLength: 32,
            }
        );
        console.log(hashedPassword)
        return hashedPassword
    }else{
        return false;
    }




}


async function hashPassword(password, email){
    const pepperFileName = process.env.NODE_ENV === "test" ? 'test/info/test_pepper.json': 'info/pepper.json';
    const saltFileName = process.env.NODE_ENV === "test" ? 'test/info/test_salt.json': 'info/salts.json';
    //Create a salt and a pepper
    const salt =  crypto.randomBytes(16).toString('hex');
    const pepper = crypto.randomBytes(16).toString('hex');
    //Store the salt and pepper:
    const storeSalt = await storePasswordInfo(saltFileName,{email:email, salt:salt})
    const storePepper =  await storePasswordInfo(pepperFileName,{email:email, pepper:pepper})
    if(storeSalt && storePepper){
        //Add the salt and the pepper to the password:
        //const saltedAndPepperPassword = password + salt + pepper;
        //const hashedPassword = crypto.createHash('sha256').update(saltedAndPepperPassword).digest('hex');
        const hashedPassword = await argon2.hash(
            password + pepper, // Combine the password and pepper
            {
                type: argon2.argon2id, // Uses the Argon2id algorithm as reccommended by the OWASP cheat sheet website
                salt: Buffer.from(salt, 'hex'), // This converts the salt to a buffer
                timeCost: 4, // 4 passes ()
                hashLength: 32, // 32 byte hash output()
            }
        );
        //console.log(hashedPassword);
        return hashedPassword
    }else{
        return false
    }
}

async function sendVerificationEmail(email, token,res, req) {
    // Construct the verification link
    //const verificationLink = `https://localhost:8080/verify?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
    // send mail with defined transport object
    // Construct the email message
    const message = await transporter.sendMail({
        from: 'webabenablogtest@gmail.com',
        to: email,
        subject: 'Verify your email address with the token',
        text: `This is your one time token: ${token}`,
        html: `This is your token: <b> ${token}</b>`
       //html: `Please click <a href="${verificationLink}">here</a> to verify your email address.`
    });
    console.log("Message sent: %s", message.messageId);
    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
    // Preview only available when sending through an Ethereal account
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(message));
    // Preview URL: https://etheral.email/message/WaQKMgKddxQDoou...
    return res.render("email-verification", { email: email, errors: false, csrfToken: req.session.csrfToken});
}





/*Login functions*/
//Login valid function
function loginValidation(reqBody){
    let isValid = true
    const passwordRegex = /(?=.{8,}$)(?=.*[a-zA-Z0-9]).*/
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    for (const inputName in reqBody) {
        const input = reqBody[inputName];
        if(
            (inputName ==="Username" && input)
            ||(!input && inputName!=="Username")
            ||(input.length < 1 && inputName!=="Username")
            ||(inputName==="password" && !passwordRegex.test(input))
            || (inputName ==="email" && !emailRegex.test(input))
            || (inputName==="passwordConfirmation") && input !== reqBody["password"]
        ){
            isValid = false;
        }
    }
    return isValid;
}

/*function verificationValidation(reqBody){
    const errorMessages = {
        verificationemail: "Please type valild email address format",
        passwordverificationtoken: "Invalid token input",
    };
    const errors = [];
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const usernameRegex= /^[a-z0-9]+$/i;
    for (const inputName in reqBody) {
        const input = reqBody[inputName];
        if(
            (!input)
            || (input.length < 1)
            || (inputName === "verificationemail" && !emailRegex.test(input))
            || (inputName === "passwordverificationtoken" && !usernameRegex.test(input))
            || ((inputName === "csrftokenvalue") && !usernameRegex.test(input))
        ){
            errors.push(errorMessages[inputName]);
            //console.log(errorMessages[inputName]);
        }
    }
    if (errors.length > 0) {
        console.log('Error')
        return { isValid: false, errors };
    } else {
        return { isValid: true };
    }
}*/


//
async function getPasswordInfo(email) {
    try {
        const pepperFileName = process.env.NODE_ENV === "test" ? 'test/info/test_pepper.json': 'info/pepper.json';
        const saltFileName = process.env.NODE_ENV === "test" ? 'test/info/test_salt.json': 'info/salts.json';
        const saltData = await fs.promises.readFile(saltFileName, 'utf8');
        const saltObj = JSON.parse(saltData);
        const userSalt = saltObj.user_info.find(u => u.email === email);
        const pepperData = await fs.promises.readFile(pepperFileName, 'utf8');
        const pepperObj = JSON.parse(pepperData);
        const userPepper= pepperObj.user_info.find(u => u.email === email);
        //console.log("The pepper: " + JSON.stringify(userPepper))
        //console.log("The salt: " + JSON.stringify(userSalt))
        if(userPepper && userSalt){
            //console.log('gets here')
            return {salt: userSalt.salt, pepper: userPepper.pepper};
        }else{
            return false;
        }
    } catch (error) {
        console.log(error);
        return false;
    }
}




async function getEncryptionKeys(email, filename) {
    try {
        const fileData = await fs.promises.readFile(filename, 'utf8');
        const fileObj = JSON.parse(fileData);
        const userObj = fileObj.user_info.find(u => u.email === email);
        if(userObj){
            //console.log('gets here')
            //console.log(userObj)
            return {userObj};
        }else{
            return false;
        }
    } catch (error) {
        console.log(error);
        return false;
    }
}




//function to validate login credentials
async function validateLoginCredentials(password, email){
    const passwordInfo = await getPasswordInfo(email)
    //console.log(passwordInfo)
    if(passwordInfo!==false){
        //console.log(saltedAndPepperedPassword)
        //const hashedPassword = crypto.createHash('sha256').update(saltedAndPepperedPassword).digest('hex');
        //console.log(hashedPassword)
        const saltedAndPepperedPassword = password + passwordInfo.pepper;
        const userQuery = {
            text: 'SELECT email, password, authmethod FROM users WHERE email = $1  AND isverified =$2',
            values: [email, true] // 24 hours in milliseconds
        };
        try {
            const result = await readOnlyPool.query(userQuery);
            const passwordComparingResult = await argon2.verify(
                result.rows[0].password, // The hashed password to verify against
                saltedAndPepperedPassword, // The salted and peppered password to verify
                {
                    type: argon2.argon2id, // Use the Argon2id algorithm
                    salt: Buffer.from(passwordInfo.salt, 'hex'), // Convert the salt to a buffer
                    timeCost: 4, // 4 passes (should match the timeCost used for hashing the password)
                    hashLength: 32, // 32 byte hash output (should match the hashLength used for hashing the password)
                }
            );
            console.log('Password comparing is ' + passwordComparingResult)

            console.log("Password stored is "+ result.rows[0].password)
            if(passwordComparingResult){
                return {credentialsValid: true, authMethod: result.rows[0].authmethod};
            }else{
                return {credentialsValid: false};
            }
        } catch (error) {
            console.log(error);
            return {credentialsValid: false};
        }

    }else{
        return {credentialsValid: false};
    }
}

async function verifyRecaptcha(response, remoteip = null) {
    const secret = process.env.recaptcha_secret_key;
    const url = 'https://www.google.com/recaptcha/api/siteverify';
    try {
        const result = await axios.post(url, null, {
            params: {
                secret,
                response,
                remoteip
            }
        });
        return result.data.success;
    } catch (error) {
        console.error('There was an error verifying recaptcha', error);
        return false;
    }
}

async function TwoFactorEmail(email, token,res, req) {
    // send mail with defined transport object
    // Construct the email message
    const message = await transporter.sendMail({
        from: 'webabenablogtest@gmail.com',
        to: email,
        subject: 'One Time PassCode for Authentication',
        text: `This is your one time token: ${token}`,
        html: `This is your token: <b style="font-size: 24px;"> ${token}</b>`
    });
    //console.log("Message sent: %s", message.messageId);
    //console.log("Preview URL: %s", nodemailer.getTestMessageUrl(message));

    return res.render("verifyToken", { message: email, errors: false, email: email, csrfToken: req.session.csrfToken});
}


async function resetPasswordEmail(email, token, res, req) {
    // send mail with defined transport object
    // Construct the email message
    const message = await transporter.sendMail({
        from: 'webabenablogtest@gmail.com',
        to: email,
        subject: 'Password reset email',
        text: `This token: ${token} has been sent to confirm that`,
        html: ` <p style="font-size: 18px;">You have requested a password reset. If this was you, paste this token: <b>${token} </b> in the Password reset verification page you were redirected to.</p>`
    });
    if(message){
        return true
    }else{
        return false

    }
    //console.log("Message sent: %s", message.messageId);
    //console.log("Preview URL: %s", nodemailer.getTestMessageUrl(message));

}

async function sendPasswordRestMailLink(email, token,creationTime) {
    // Construct the verification link
    const passwordResetLink = `https://localhost:8080/changePassword?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}&creationTime=${encodeURIComponent(creationTime)}`;
    // send mail with defined transport object
    // Construct the email message
    const message = await transporter.sendMail({
        from: 'webabenablogtest@gmail.com',
        to: email,
        subject: 'Password Reset',
        text: `Please click the following link to reset your password: ${passwordResetLink}`,
        html: ` <p style="font-size: 18px;">Please click <a href="${passwordResetLink}">here</a> to reset your password</p>`
    });
    //console.log("Message sent: %s", message.messageId);
    // Preview only available when sending through an Ethereal account
   // console.log("Preview URL: %s", nodemailer.getTestMessageUrl(message));
    if(message){
        return true
    }else{
        return false

    }
}





//Validation input functions
 function blogFormDataValidation(reqBody){
     const errorMessages = {
         blogTitle: "There is an invalid input in your blog title",
         blogDescription: "There is an invalid input in your blog description",
         blogData: "There is an invalid input in your blog data",
     };
     const errors = [];
     const regex = /^[a-zA-Z0-9.,!?\s"]+$/;
     //const regex = /^[a-zA-Z0-9\s\.\?\!\,\-]+$/g // regular expression to match letters and punctuations
    for (const inputName in reqBody) {
        const input = reqBody[inputName];
       // console.log("The input is : " + input)
        if (!regex.test(input) || !input || input.length < 2 ) {
            console.log("The error is in: "+ input)
            errors.push(errorMessages[inputName])
            //errors.push(input)
           // errors.push(input);
        }
    }
    if (errors.length > 0) {
        console.log('Error')
        return { isValid: false, errors };
    } else {
        return { isValid: true };
    }
}



function validateInputsAll(reqBody) {
    const errors = [];
    const regex = /^[a-zA-Z0-9?!,.\\s]+$/
    //const XSSScriptRergex =
    //const regex = /^[a-zA-Z0-9\s\.\?\!\,\-]+$/g // regular expression to match letters and punctuations
    //const regex = /^[a-zA-Z,.!?'"()\s]+$/; // regular expression to match letters and punctuations

    for (const inputName in reqBody) {
        const input = reqBody[inputName];
        console.log("Length is " + input.length)
        console.log("The input is: " + input);
        if (!input || input.length < 1) {
            errors.push(`There is an error in the "${inputName}" input`);
        }
    }
    if (errors.length > 0) {
        console.log('Error')
        return { isValid: false, errors };
    } else {
        return { isValid: true };
    }
}

function validateInput(inputJson){
    const errors = []
    const whiteListedInput = /^[a-zA-Z0-9.,!?\s"]+$/; //The right input regex
    for (const inputName in inputJson) {
        const input = inputJson[inputName]
        console.log(whiteListedInput.test(input))
        if (input === "" || input.length < 2 || whiteListedInput.test(input)===false) {
            console.log(input)
            errors.push("Your " + input + " contains a character that may not be allowed \n" +
                "Kindly ensure that the input contains only alphabets, letters, numbers and basic punctuation")
        }
    }
    if(errors.length >0){
        return {isValid: false, errors}
    }else{
        return{isValid: true};
    }
}









function searchBarValidation(input){
    const searchRegex =  /^[a-zA-Z0-9\s]+$/;
    if(!searchRegex.test(input)){
        return false
    }else{
        return true;
    }
}

function loginSessionIDRegenerate(email, res, req){
    const nameQuery = {
        text: 'SELECT firstname FROM users WHERE email = $1',
        values: [email],  // 24 hours in milliseconds
    }
    req.session.regenerate((err)=>{
        if (err) {
            console.error(err);
        }else{
            //Get users email and place it in the session
            req.session.usermail = email;
            //Set the session firstname
            readOnlyPool.query(nameQuery).then((results)=>{
                req.session.firstname= results.rows[0].firstname;
                res.redirect('/blogDashboard');
            })


        }
    })
}





 function encryptWord(word){
    //const encryptionKey = crypto.randomBytes(32);
    //console.log("Printed encryption key: " + encryptionKey)
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', process.env.encryption_key, process.env.encryption_iv);
    let encryptedWord = cipher.update(word, 'utf8', 'hex') + cipher.final('hex');
    // Get the authentication tag, this is used to provide an additional layer of security
    //It is to make sure data doesn't get changed in transmission
    const authenticationTag = cipher.getAuthTag().toString('hex');
    //console.log( "Encrypted word" + encryptedWord)
    console.log('Authentication tag is ' + authenticationTag)
    //console.log('encrypt iv ' + iv.toString('hex'))
     return{
         encryptionKey: process.env.encryption_key,
         authenticationTag: authenticationTag,
         encryptedWord: encryptedWord,
         iv: process.env.encryption_iv
     }
}


 function decryptWord(encryptedWordObject){
    const ivBuffer = Buffer.from(encryptedWordObject.iv, 'hex');
    const authTagBuffer = Buffer.from(encryptedWordObject.authenticationTag, 'hex');
    //Get encryption key from file name:
     // console.log(encryption_key_obj)
    const encryption_key = Buffer.from(encryptedWordObject.encryptionKey);
    //console.log(encryption_key)
    if(encryption_key){
        const decipher = crypto.createDecipheriv('aes-256-gcm',encryption_key , ivBuffer, {
            authTagLength: 16,
        });
        decipher.setAuthTag(authTagBuffer);
        // Decrypt the encrypted secret using the decipher object
        let decryptedWord = decipher.update(encryptedWordObject.encryptedWord, 'hex', 'utf8');
        decryptedWord += decipher.final('utf8');
        //console.log("Decrypted word:" + decryptedWord)
        //console.log("Decrypted word " + decryptedWord)
        return decryptedWord;
    }else{
        return false;
    }
}


async function encryptTotpInfo(word, email){
    const keyFileName = process.env.NODE_ENV === "test" ? 'test/info/test_keys.json': 'info/keys.json';
    const encryptionKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    let encryptedWord = cipher.update(word, 'utf8', 'hex') + cipher.final('hex');
    // Get the authentication tag, this is used to provide an additional layer of security
    //It is to make sure data doesn't get changed in transmission
    const authenticationTag = cipher.getAuthTag().toString('hex');
    //console.log('Authentication tag is ' + authenticationTag)
    //console.log('encrypt iv ' + iv.toString('hex'))
    encryptedWord = encryptedWord + iv.toString('hex') + authenticationTag;
    let encryption_key_data = {email:email, encryptionKey: encryptionKey}
    let storedKeys = await storePasswordInfo(keyFileName, encryption_key_data)
    if(storedKeys){
        //console.log("Encrypted word " + encryptedWord)
        return encryptedWord
    }else{
        return false
    }

}

async function decryptTotpInfo(storedEncryptedWord, email){
    const keyFileName = process.env.NODE_ENV === "test" ? 'test/info/test_keys.json': 'info/keys.json';
    const iv = storedEncryptedWord.slice(-56, -32);// Get the next 24 characters after the last 32 characters
    const encryptedWord = storedEncryptedWord.slice(0,  storedEncryptedWord.indexOf(iv)); //Get from the beginning till the iv
    const authenticationTag = storedEncryptedWord.slice(-32); // Get the last 32 characters of the string
    //console.log('Decryption Authentication tag is ' +authenticationTag)
    //console.log('iv is ' + iv)
     const ivBuffer = Buffer.from(iv, 'hex');
    const authTagBuffer = Buffer.from(authenticationTag, 'hex');
    //Get encryption key from file name:
    const encryption_key_obj = await getEncryptionKeys(email, keyFileName)
    //console.log(encryption_key_obj)
    const encryption_key = Buffer.from(encryption_key_obj.userObj.encryptionKey);
    //console.log(encryption_key)
    if(encryption_key){
        const decipher = crypto.createDecipheriv('aes-256-gcm',encryption_key , ivBuffer, {
            authTagLength: 16,
        });
        decipher.setAuthTag(authTagBuffer);
        // Decrypt the encrypted secret using the decipher object
        let decryptedWord = decipher.update(encryptedWord, 'hex', 'utf8');
        decryptedWord += decipher.final('utf8');
        //console.log("Decrypted word " + decryptedWord)

        return decryptedWord;
    }else{
        return false;
    }

}


//Sanitize input against Server side templating:
/*All the application get routes*/
//Routes

//Any unassigned routes.

app.get('/',(req, res) => {
    //console.log('Original CSRF Token: ', req.session.csrfToken)
    res.render('index', {errors: false, message: false, csrfToken: req.session.csrfToken})
});

app.get('/sign-up', (req, res) => {
    res.render('sign-up', {errors: false, message: false,  csrfToken: req.session.csrfToken})
});


app.get('/email-verification', (req,res)=>{
    res.render('email-verification', {email: false, csrfToken: req.session.csrfToken })
})

app.get('/setup-totp', (req, res)=>{
    if(req.session.verifiedTotpUserEmail){
        const secret = speakeasy.generateSecret({ length: 20 });
        qrCode.toDataURL(secret.otpauth_url, function(err, qrCodeData) {
            if (err) {
                console.log(err);
                res.render('setup-totp', { qrCodeData: null, secret: null, errors:"An error occurred please try again", email: null, message: false, csrfToken: req.session.csrfToken });
            } else {
                res.render('setup-totp', { qrCodeData: qrCodeData, secret: secret.base32, errors:false, email: req.session.verifiedTotpUserEmail, message: 'Your email has been verified', csrfToken: req.session.csrfToken});
            }
        });

    }else{
            return res.redirect('/')
    }
})
app.get('/verify-totp', (req, res)=>{
    if( req.session.totpLoginUserMail){
        res.render('verify-totp', {errors: false , csrfToken: req.session.csrfToken})

    }else{
        return res.redirect('/')
    }

})

app.get('/resetPassword', (req, res)=>{
    res.render('resetpassword', {errors: false, csrfToken: req.session.csrfToken, message: false})
})

app.get('/changePassword', (req, res)=>{
    // Extract the email and token from the URL query string
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const tokenRegex= /^[a-z0-9]+$/i;
    const currentTimeRegex = /^\d{13}$/
    const email = req.query.email; // Data needs to be sanitized before being passed.
    const token = req.query.token;
    const queryCreationTime = req.query.creationTime;
    const thirtyMinuteTimer = 1000*60*30;
    const expirationTime =  queryCreationTime + thirtyMinuteTimer
    const currentTime = Date.now()
    //Input validation is utilised her to prevent server side encry
    if(emailRegex.test(email) && tokenRegex.test(token)&& currentTimeRegex.test(queryCreationTime)){
        if((req.signedCookies.passwordResetCookie===token) && (currentTime < expirationTime)){
            res.render('changePassword', {authorized: true, email: email, errors: false, csrfToken: req.session.csrfToken, message: false})
        }else{
            res.render('changePassword', {authorized: false, errors: false, csrfToken: null, message: false, email: null})

        }
    }else{
        res.render('changePassword', {authorized: false, errors: false, csrfToken: null, message: false, email: null})

    }
})



/*Blog gets*/
app.get('/blogDashboard', (req, res)=>{
    //Saving
    if(!req.session.usermail ){
        //If the user was timed out due to being inactive for 30 minutes, then they get a message in order to improve usability.
        if(userTimedOut) {
            res.clearCookie('sessionId');
            res.render('index', {errors:false, message: "You were logged out due to being inactive for 30 minutes. So sorry for the inconvenience.", csrfToken: req.session.csrfToken})
        }else{
            res.redirect('/')
        }
    }else{
        //console.log('Session ID:', req.sessionID);
        //console.log('CSRF Token', req.session.csrfToken)
        //Get all the blog posts from the database:
        const getAllPostQuery = {
            text: 'SELECT * FROM blogdata ORDER BY datecreated DESC ',
        };
        readOnlyPool.query(getAllPostQuery, (err, result)=>{
            if (err){
                console.error(err);
                res.render('blogDashboard', {firstname: req.session.firstname, errors: "There was an error retrieving the posts", post: '', usermail:req.session.usermail,  csrfToken: req.session.csrfToken })
            }else{
                const blogPosts = result.rows;
                res.render('blogDashboard', {firstname: req.session.firstname, errors: false, posts: blogPosts, usermail: req.session.usermail,  csrfToken: req.session.csrfToken })
            }
        })
    }
})
app.get('/editblog/:id', async(req, res)=>{
    if (req.session.usermail){
        const blogId = req.params.id;
        const getBlogPostQuery = {
            text: 'SELECT * FROM blogData WHERE id = $1 AND blogAuthor =$2',
            values: [blogId, req.session.usermail]
        };
        pool.query(getBlogPostQuery, (err, result)=>{
            if(err){
                res.render('editBlog', {errors: 'There was an error with updating the blog', post: '', firstname: req.session.firstname, csrfToken: req.session.csrfToken})
            }else{
                const blogPost = result.rows[0]
                console.log(blogPost)
                if(blogPost){
                    res.render('editBlog', {errors: false, post: blogPost, firstname: req.session.firstname, csrfToken: req.session.csrfToken})
                }else{
                    const getAllPostQuery = {
                        text: 'SELECT * FROM blogdata ORDER BY datecreated DESC ',
                    };

                    readOnlyPool.query(getAllPostQuery, (err, result)=>{
                        if (err){
                            console.error(err);
                            res.render('blogDashboard', {firstname: req.session.firstname, errors: "There was an error retrieving the posts", post: '', usermail:req.session.usermail,  csrfToken: req.session.csrfToken })
                        }else{
                            const blogPosts = result.rows;
                            res.render('blogDashboard', {firstname: req.session.firstname, errors: "You are not authorised to edit that blog post", posts: blogPosts, usermail: req.session.usermail,  csrfToken: req.session.csrfToken })
                        }
                    })
                }
            }
        })

    }else{
        //If the user was timed out due to being inactive for 30 minutes, then they get a message in order to improve usability.
        if(userTimedOut) {
            res.clearCookie('sessionId');
            res.render('index', {errors:false, message: "You were logged out due to being inactive for 30 minutes. So sorry for the inconvenience.", csrfToken: req.session.csrfToken})
        }else{
            res.redirect('/')
        }

    }
})

app.get('/addBlogPost', (req, res)=>{
    if(!req.session.usermail){
        //If the user was timed out due to being inactive for 30 minutes, then they get a message in order to improve usability.
        if(userTimedOut) {
            res.clearCookie('sessionId');
            res.render('index', {errors:false, message: "You were logged out due to being inactive for 30 minutes. So sorry for the inconvenience.", csrfToken: req.session.csrfToken, doubleSubmitCookie: req.session.doubleSubmitCookie})
        }else{
            res.redirect('/')
        }
    }else{
        //console.log(req.session.token)
        res.render('addBlogPost', {errors:false, csrfToken: req.session.csrfToken, doubleSubmitCookie: req.session.doubleSubmitCookie})

    }
})


app.get('/readblog/:id', (req, res) => {
    if(req.session.usermail){
        const blogId = req.params.id;
        const getBlogPostQuery = {
            text: 'SELECT * FROM blogData WHERE id = $1',
            values: [blogId]
        };
        readOnlyPool.query(getBlogPostQuery, (err, result) => {
            if (err) {
                console.error(err);
                res.render('error', {errors: 'There was an error retrieving the blog post', firstname: req.session.firstname, post:'' });
            } else {
                const blogPost = result.rows[0];
                res.render('fullBlog', {post: blogPost, errors:false, firstname: req.session.firstname});
            }
        });
    }else{
        //If the user was timed out due to being inactive for 30 minutes, then they get a message in order to improve usability.
        if(userTimedOut) {
            res.clearCookie('sessionId');
            res.render('index', {errors:false, message: "You were logged out due to being inactive for 30 minutes. So sorry for the inconvenience.", csrfToken: req.session.csrfToken})
        }else{
            res.redirect('/')
        }
    }

});

app.get('/search', (req, res) => {
    if(req.session.usermail) {
        const query = escapeInput(req.query.search);
        if(searchBarValidation(query)){
            console.log(query)
            // Use a prepared statement to avoid SQL injection attacks
            const likeQuery = {
                name: 'search-posts',
                text: 'SELECT * FROM blogdata WHERE blogtitle ILIKE $1 OR bloginfo ILIKE $1 OR blogauthor ILIKE $1 OR blogdescription ILIKE $1',
                values: [`%${query}%`],
            };
            readOnlyPool.query(likeQuery, (err, result) => {
                if (err) {
                    console.error('Error executing query', err);
                    return res.status(500).send('An error occurred while searching for posts.');
                }
                res.render('search-results', {results: result.rows, usermail: req.session.usermail, errors: false});
            });
        }else{
            console.log(query)
            res.render('search-results', {results: 0, usermail: req.session.usermail, errors: "Please try searching something else "});
        }
    }else{
        //If the user was timed out due to being inactive for 30 minutes, then they get a message in order to improve usability.
        if(userTimedOut) {
            res.clearCookie('sessionId');
            res.render('index', {errors:false, message: "You were logged out due to being inactive for 30 minutes. So sorry for the inconvenience.", csrfToken: req.session.csrfToken})
        }else{
            res.redirect('/')
        }
    }
});

app.get('*', (req,res)=>{
    res.redirect('/')
})






/*All the application post routes*/
app.post('/sign-up',  async (req,res)=>{
        const captchaResponse = req.body['g-recaptcha-response'];
        const captchaSuccess = await verifyRecaptcha(captchaResponse, req.ip);
        console.log(captchaSuccess)
        if(captchaSuccess || process.env.TEST_TYPE==='signUp') {
            if (signUpValidation(req.body).isValid) {
                console.log('gets here')
                const escapedReqBody = escapeAllInput(req.body)
                const email = escapedReqBody.email;
                const password = escapedReqBody.password;
                const username = escapedReqBody.username;
                const authMethod = escapedReqBody.authmethod;
                //Check if the user already exists in the system:
                userExistsCheck(email).then(async (userExists) => {
                    if (userExists) {
                        //console.log(res.toString())
                        //Redirect the user to the email verification page in order to prevent account enumeration, but no actual email will be sent to that user
                        //since the user already exists in the system.
                        res.render('email-verification', {
                            email: email,
                            errors: false,
                            csrfToken: req.session.csrfToken
                        })
                    } else {
                        //If user does not already exists in the password then we can hash the password
                        //Call the hashedPassword which is a function that generated a random hash.
                        const hashedPassword = await hashPassword(password, email)
                        console.log(hashedPassword)
                        if (hashedPassword) {
                            //Process with hashed Password has gone well without any errors and thus process can continue.
                            // Generate a unique verification token for email verification
                            const token = crypto.randomBytes(20).toString('hex');
                            const creationTime = Date.now();
                            // Insert the new user into the "users" table
                            const query = {
                                text: 'INSERT INTO users (email, password, isverified, verificationtoken, firstname, creationtime, authmethod) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                                values: [email, hashedPassword, false, token, username, creationTime, authMethod]
                            };
                            pool.query(query)
                                .then(() => sendVerificationEmail(email, token, res, req))
                                .catch(err => console.error(err))
                        } else {
                            console.log("Password unsuccessfully hashed");
                            const errors = [];
                            errors.push("There was an error during the sign-up process, please try again later");
                            res.render('sign-up', {errors: errors, message: false, csrfToken: req.session.csrfToken})
                        }
                    }
                });
            } else {
                console.log('Invalid data or csrf token')
                const errors = signUpValidation(req.body).errors;
                res.render('sign-up', {errors: errors, message: false, csrfToken: req.session.csrfToken})
            }
        }else{
            res.render('sign-up',
                {
                    errors: false,
                    message: "Please tick the reCAPTCHA checkbox to prove that you are human and not a robot.",
                    csrfToken:
                    req.session.csrfToken
                })
        }
})

app.post('/email-verification',  (req, res) => {
    //console.log('this got triggered')
    // Extract the email and token from the URL query string
    const email = req.body.verificationemail;
    console.log(email)
    const token = req.body.userverificationtoken;
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const usernameRegex= /^[a-z0-9]+$/i;
    if(!emailRegex.test(email) ||!usernameRegex.test(token)|| token==="" || email===""){
        //console.log('in here')
        res.render('email-verification', {email: email, errors: "The token you have inputted is invalid", csrfToken: req.session.csrfToken})
    }else{
        const currentTime = Date.now()
        //this value is for testing
        //const timeDifference = 5 * 60 * 1000;
        const timeDifference = 24 * 60 * 60 * 1000;
        //Check if the token in the link is correct as the one in the database
        const tokenQuery = {
            text: 'SELECT verificationtoken, authmethod FROM users WHERE email = $1 AND $2 - creationtime < $3',
            values: [email, currentTime, timeDifference] // 24 hours in milliseconds
        };
        pool.query(tokenQuery, (err, result) => {
            if (err) {
                console.log(err);
            } else {
                console.log(result.rows[0].verificationtoken)
                if (result.rows.length > 0 && token=== result.rows[0].verificationtoken) {
                    //Adding an updated token to ensure that the link is a one time click.
                    const updateToken = ""
                    const updateQuery = {
                        text: 'UPDATE users SET isverified = $1, verificationtoken = $2 WHERE email = $3 AND verificationtoken = $4',
                        values: [true, updateToken, email, token],
                    };
                    pool.query(updateQuery)
                        .then(()=>{
                            const authMethod = result.rows[0].authmethod;
                            if(authMethod==="email"){
                                //Take them to the
                                res.render('index', {message: 'Your account has been verified', errors: false, csrfToken: req.session.csrfToken})
                            }else if(authMethod==="totp"){
                                req.session.verifiedTotpUserEmail = email
                                res.redirect('/setup-totp')
                                //res.render('setUpTotp', {message: 'Your account has been verified', errors: false})
                            }
                        }).catch(err=>console.log(err));
                }else{
                    res.render('email-verification', {email: email, errors: "The token you have inputted is invalid", csrfToken: req.session.csrfToken})
                }
            }
        })
    }
})

app.post('/login', async (req, res)=>{
    const captchaResponse = req.body['g-recaptcha-response'];
    const captchaSuccess = await verifyRecaptcha(captchaResponse, req.ip);
    //console.log("Captcha success: " + captchaSuccess)
    if(captchaSuccess) {
        if (loginValidation(req.body)) {
            const escapedLoginBody = escapeAllInput(req.body);
            const email = escapedLoginBody.email;
            const password = escapedLoginBody.password;
            const userValid = await validateLoginCredentials(password, email);
            if (userValid.credentialsValid) {
                const authenticationType = userValid.authMethod;
                if (authenticationType === "email") {
                    //const token=   Math.floor(100000 + Math.random() * 900000);
                    // Generate a unique verification token for email Two factor Authentication.
                    const token = crypto.randomBytes(20).toString('hex');
                    let creationTime = Date.now();
                    const selectQuery = {
                        text: 'SELECT otp, used FROM otps WHERE email = $1',
                        values: [email] // 24 hours in milliseconds
                    };
                    pool.query(selectQuery)
                        .then((result) => {
                            if (result.rows.length > 0) {
                                const updateQuery = {
                                    text: 'UPDATE otps SET used = $1, otp = $2, creationtime= $3 WHERE email = $4',
                                    values: [false, token, creationTime, email]
                                };
                                pool.query(updateQuery);
                            } else {
                                //This means that there has been no otp set before
                                const query = {
                                    text: 'INSERT INTO otps (email, otp, used, creationtime) VALUES ($1, $2, $3, $4)',
                                    values: [email, token, false, creationTime]
                                };
                                pool.query(query)
                            }
                        })
                    //Two factor Authentication.
                    await TwoFactorEmail(email, token, res, req)
                } else if (authenticationType === "totp") {
                    req.session.totpLoginUserMail = email;
                    res.redirect('/verify-totp')
                }

            } else {
                console.log('Invalid credentials')
                res.render('index', {
                    errors: "Email and/or password is incorrect",
                    message: false,
                    qrCodeData: false,
                    csrfToken: req.session.csrfToken
                })
            }
            //console.log(email,password)
        } else {
            console.log('Invalid user data')
            res.render('index', {
                errors: "Email and/or password is incorrect",
                message: false,
                csrfToken: req.session.csrfToken
            })
        }
    }else{
        res.render('index', {
            errors: false,
            message: "Please tick the reCAPTCHA checkbox to prove that you are human and not a robot.",
            csrfToken: req.session.csrfToken
        })

    }

})

app.post('/setup-totp',  async(req, res)=>{
    const qrCodeDataSrc = req.body.qrCodeData;
    let secret = req.body.secret;
    let email = req.body.email;
    const checkedBox = req.body.totpconfirmation;
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const secretRegex= /^[a-z0-9]+$/i;
    if(!emailRegex.test(email) || !secretRegex.test(secret) || checkedBox !=="true"||secret===""||email===""){
            res.render('setup-totp', { qrCodeData: qrCodeDataSrc, secret: secret.base32, email: email, errors: "An error occured, kindly refresh the page and try again", csrfToken: req.session.csrfToken})
    }else{
        email = escapeInput(email);
        secret= escapeInput(secret);
        const encrypted_secret = await encryptTotpInfo(secret, email);
        if(encrypted_secret){
            //const hashedSecret = crypto.createHash('sha256').update(secret).digest('hex');
            console.log(encrypted_secret)
            const insertSecretQuery = {
                text: 'INSERT INTO totp (email, secret) VALUES ($1, $2)',
                values: [email, encrypted_secret]
            };
            pool.query(insertSecretQuery)
                .then(()=>
                {
                    delete req.session.verifiedTotpUserEmail;
                    res.render('index', {message: 'Your TFA has been set-up, you can now login securely', errors: false, csrfToken: req.session.csrfToken})

                })
                .catch((err)=>{
                    console.log(err)
                    res.render('setup-totp', { qrCodeData: qrCodeDataSrc, secret: secret.base32, email: email, errors: "An error occured, kindly refresh the page and try again", csrfToken: req.session.csrfToken})
                })

        }


    }
})


app.post('/verify-totp', async function(req, res) {
    const userEmail = req.session.totpLoginUserMail
    const selectSecret = {
        text: 'SELECT secret FROM totp WHERE email = $1',
        values: [userEmail] // 24 hours in milliseconds
    };
    let results = await pool.query(selectSecret);
    results = results.rows[0].secret
    console.log(results)
    const decrypted_secret = await decryptTotpInfo(results, userEmail)
    console.log(decrypted_secret)
    if(decrypted_secret){
        const token = req.body.token;
        const inputRegex= /^[a-z0-9]+$/i;
        const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
        if( inputRegex.test(token)|| token==="" || emailRegex.test(userEmail) || userEmail===""){
            const verified = speakeasy.totp.verify({ secret: decrypted_secret, encoding: 'base32', token: token, window: 1 });
            if (verified) {
                //Session regeneration of authentication confirmation to prevent session hijacking
                delete req.session.totpLoginUserMail
                loginSessionIDRegenerate(userEmail,res,req)
            } else {
                res.render('verify-totp', {email: userEmail, errors:'Invalid token', csrfToken: req.session.csrfToken});
            }
        }else{
            res.render('verify-totp.ejs', {email: userEmail, errors:'There was an error in your input', csrfToken: req.session.csrfToken});
        }
    }else{
        res.render('verify-totp.ejs', {email: userEmail, errors:'There was an error during the process', csrfToken: req.session.csrfToken});

    }

});

app.post('/twofa', (req,res)=>{
    //Restrict input to only numeric values.
        const twoFactorRegex = /^[0-9]+$/
           const escapedBody = escapeAllInput(req.body)
           let currentTime = Date.now();
           //const timeDifference = 24 * 60 * 60 * 1000; //24 hrs testing
           const timeDifference = 5 * 60 * 1000;
           const email = escapedBody.email;
           const otp = escapedBody.verificationtoken;
           //Check if the token in the link is correct as the one in the database
           const twofatokenquery = {
               text: 'SELECT otp FROM otps WHERE otp = $1 AND $2 - creationtime < $3 AND used = $4 AND email = $5 ',
               values: [otp, currentTime,timeDifference, false, email],  // 24 hours in milliseconds
           };

           const deleteTokenQuery = {
               text: 'DELETE FROM otps WHERE otp = $1  AND email= $2',
               values: [otp, email] // 24 hours in milliseconds
           };
           const nameQuery = {
               text: 'SELECT firstname FROM users WHERE email = $1',
               values: [email],  // 24 hours in milliseconds
           }
           pool.query(twofatokenquery).then((result)=>{
               //console.log(result.rows[0]);
               if(result.rows.length > 0){
                   pool.query(nameQuery)
                       .then((results)=>{
                           //Session regeneration of authentication confirmation to prevent session hijacking
                          req.session.regenerate((err)=>{
                               if (err) {
                                   console.error(err);
                               }else{
                                   //Get users email and place it in the session
                                   req.session.usermail = email;
                                   //Set the session firstname
                                   req.session.firstname= results.rows[0].firstname;
                                   res.redirect('/blogDashboard');
                                   pool.query(deleteTokenQuery)
                               }
                           })
                       })
               }else{
                   res.render('verifyToken', {errors:'Invalid token', email:email, message: email, csrfToken: req.session.csrfToken})
               }
           })
})




app.post('/logout', (req, res)=> {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
            res.status(500).send('Server Error');
        } else {
            res.clearCookie('sessionId');
            res.redirect('/');
        }
    });
})

app.post('/passwordReset', async(req,res)=>{
    const captchaResponse = req.body['g-recaptcha-response'];
    const captchaSuccess = await verifyRecaptcha(captchaResponse, req.ip);
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const email = req.body.email
    if(captchaSuccess){
        if(emailRegex.test(email)){
            let userExists =await  userExistsCheck(email);
            if(userExists){
                const authenticationType ={
                    text: 'SELECT authmethod FROM users WHERE  email = $1 ',
                    values: [email],  // 24 hours in milliseconds

                }
                let authenticationQuery = await writeOnlyPool.query(authenticationType)
                let queryResults = authenticationQuery.rows[0].authmethod
                let creationTime = Date.now()
                console.log(queryResults)
                if(queryResults==='email'){
                    const passwordResetToken = crypto.randomBytes(20).toString('hex');
                    let sendVerificationLink =  await sendPasswordRestMailLink(email, passwordResetToken, creationTime)
                    if(sendVerificationLink){
                        res.cookie('passwordResetCookie', passwordResetToken, {
                            maxAge: 30 * 60 * 1000, //30 minutes the the cookie will be expired
                            httpOnly: true, // cookie cannot be accessed from JavaScript code
                            secure: true, // cookie can only be sent over HTTPS
                            sameSite: 'lax', // cookie can only be sent on same-site requests
                            signed: true,
                            path: '/changePassword'
                        });

                        res.render('passwordresetverification', {
                            email: email,
                            message: false,
                            errors: false,
                            csrfToken: req.session.csrfToken
                        })


                    }
                }else if(queryResults==='totp'){
                    res.render('otpPasswordReset', {
                        email:email,
                        errors: false,
                        csrfToken: req.session.csrfToken
                    })
                }


            }else{
                res.render('passwordresetverification', {
                    email: email,
                    message: false,
                    errors: false,
                    csrfToken: req.session.csrfToken
                })
            }
        }else{
            res.render('resetpassword', {
                message: false,
                errors: 'Please input a correct email address format',
                csrfToken: req.session.csrfToken
            })
        }
    }else{
        res.render('resetpassword', {
            message: false,
            errors: 'Please tick the reCAPTCHA checkbox to prove that you are human and not a robot.',
            csrfToken: req.session.csrfToken
        })
    }
})

app.post('/changePassword', async(req,res)=>{
    const captchaResponse = req.body['g-recaptcha-response'];
    const captchaSuccess = await verifyRecaptcha(captchaResponse, req.ip);
    const passwordRegex = /(?=.{8,}$)(?=.*[a-zA-Z0-9]).*/
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const email = req.body.email;
    const password = req.body.newpassword
    if(captchaSuccess){
        //console.log(email, password)
        if(emailRegex.test(email) && passwordRegex.test(password)){
            const salt =  crypto.randomBytes(16).toString('hex');
            const pepper = crypto.randomBytes(16).toString('hex');
            let userPasswordData = {
                email: email,
                pepper: pepper,
                salt: salt,
                newPassword: password
            }
            let rehashNewPassword = await reHashNewPassword(userPasswordData)
            if(rehashNewPassword){
                const updatePasswordQuery ={
                    text: 'UPDATE users SET password = $1 WHERE  email = $2 ',
                    values: [rehashNewPassword, email],  // 24 hours in milliseconds
                }
                let updatePassword = await writeOnlyPool.query(updatePasswordQuery)
                if(updatePassword){
                    res.clearCookie('passwordResetCookie')
                    res.render('index', {
                        message: 'Your password has been changed successfully. You can now login with your new password',
                        errors: false,
                        csrfToken: req.session.csrfToken,
                    })
                }
            }else{
                res.render('changePassword', {
                    email: email,
                    authorized: true,
                    message: false,
                    errors: 'There was an error that occured during the reset password process. Kindly refresh and try again',
                    csrfToken: req.session.csrfToken
                })

            }

        }else{
            res.render('changePassword', {
                email: email,
                authorized: true,
                message: false,
                errors: 'Your data input may not be valid',
                csrfToken: req.session.csrfToken
            })
        }

    }else{
        res.render('changePassword', {
            email: email,
            authorized: true,
            message: false,
            errors: 'Please tick the reCAPTCHA checkbox to prove that you are human and not a robot.',
            csrfToken: req.session.csrfToken
        })

    }
})


app.post('/verifypasswordtotp', async(req,res)=>{
    const totpToken = req.body.token
    const userEmail = req.body.email
    const inputRegex= /^[a-z0-9]+$/i;
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    if(inputRegex.test(totpToken) && emailRegex.test(userEmail)){
        const selectSecret = {
            text: 'SELECT secret FROM totp WHERE email = $1',
            values: [userEmail] // 24 hours in milliseconds
        };
        let results = await pool.query(selectSecret);
        results = results.rows[0].secret
        //console.log(results)
        const decrypted_secret = await decryptTotpInfo(results, userEmail)
        if(decrypted_secret){
            const verified = speakeasy.totp.verify(
                { secret: decrypted_secret,
                    encoding: 'base32',
                    token: totpToken,
                    window: 1
                });
            if(verified){
                res.render('changePassword', {
                    authorized: true,
                    csrfToken: req.session.csrfToken,
                    email: userEmail,
                    message: false,
                    errors: false,
                })
            }else{
                res.render('otpPassworReset', {
                    csrfToken: req.session.csrfToken,
                    email: userEmail,
                    errors: "Your token is invalid",
                })

            }


        }
        //console.log(decrypted_secret)



    }else{
        res.render('otpPasswordReset', {
            email: userEmail,
            message: false,
            errors: 'Invalid data. Please check your user input',
            csrfToken: req.session.csrfToken
        })

    }
})





app.post('/verifyPasswordReset', async(req, res)=>{
    const email = req.body.verificationemail;
    const verificationToken = req.body.passwordverificationtoken;
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const usernameRegex= /^[a-z0-9]+$/i;
    if(emailRegex.test(email) && usernameRegex.test(verificationToken)){
        const confirmTokenQuery ={
            text: 'SELECT passwordreset FROM users WHERE email = $1',
            values: [email],
        }
        let storedTokenQuery = await readOnlyPool.query(confirmTokenQuery)
        let queryResults = storedTokenQuery.rows.passwordreset
        console.log(queryResults)
        if(verificationToken===queryResults){
            res.render('changePassword', {
                csrfToken: req.session.csrfToken,
                email: email,
                message: false,
                errors: false,
            })
        }else{
            res.render('passwordresetverification', {
                email: email,
                message: false,
                errors: 'Invalid user token. Please try again',
                csrfToken: req.session.csrfToken
            })
        }


    }else{
        res.render('passwordresetverification', {
            email: email,
            message: false,
            errors: 'Invalid data. Please check your input',
            csrfToken: req.session.csrfToken
        })

    }


})




/*Blog post quotes*/
app.post('/deleteblog/:id', (req, res)=>{
    if(req.session.usermail){
        const id = req.params.id;
        const deletePostQuery = {
            text: 'DELETE FROM blogdata WHERE id = $1 AND blogauthor = $2',
            values: [id, req.session.usermail] // 24 hours in milliseconds
        };
        pool.query(deletePostQuery, (err, results)=>{
            if(err){
                console.log(err)
                res.render('blogDashboard', {errors: 'Error deleting the blog post', firstname: req.session.usermail, post:'', csrfToken: req.session.csrfToken })
            }else{
                res.redirect('/blogDashboard')

            }
        })

    }else{
        res.redirect('/')
    }
})




app.post('/editblog/:id', (req, res)=>{
    if(req.session.usermail){
        const blogId = req.params.id;
        const getBlogPostQuery = {
            text: 'SELECT * FROM blogData WHERE id = $1',
            values: [blogId]
        };

        pool.query(getBlogPostQuery,(err, result)=>{
            if(err){
                res.render('editBlog', {errors: 'There was an error with updating the blog', post: '', firstname: req.session.usermail, csrfToken: req.session.csrfToken})

            }else{

                //used to have escape input function on it.
                const blogPost = result.rows[0]
                const blogTitle = req.body.blogtitle;
                const blogDescription = req.body.blogdescription;
                const blogInfo = req.body.bloginfo;
                //console.log(blogInfo, blogDescription, blogTitle)
                const timeCreated = Date.now().toString();
                const dateCreated = new Date(parseInt(timeCreated)).toISOString().slice(0, 10);
                //let allData = [blogTitle, blogDescription, blogInfo]
                //let allData = { blogTitle: blogTitle, blogDescription:blogDescription , blogData: blogInfo };

                /*if(blogFormDataValidation(allData).isValid){*/
                    const updateQuery = {
                        text: 'UPDATE blogData SET blogtitle = $1, bloginfo = $2, datecreated= $3, blogdescription = $4 WHERE id = $5',
                        values: [blogTitle, blogInfo, dateCreated, blogDescription, blogId]
                    };
                    pool.query(updateQuery).then((result)=>{
                        res.redirect('/blogDashboard')
                    }).catch((err)=>{
                        console.log(err)
                        return res.render("editBlog", {errors: 'There was an error when trying to edit your blog', firstname: req.session.firstname, post:blogPost, csrfToken: req.session.csrfToken});
                    })
               // }

                /*else{
                    return res.render("editBlog", {errors: 'There is an error in your input', firstname: req.session.firstname, post:blogPost, csrfToken: req.session.csrfToken});

                }*/
            }
        })
    }else{
        res.redirect('/')
    }
})


app.post('/addBlogPost', (req, res)=>{
    //const errors = validationResult(req);
    if(req.session.usermail){

     /*    console.log("invalid token")
     if(!blogFormDataValidation(req.body).isValid) {
            //const escapedInputPart2 = encodeURIComponent(req.body)
            //console.log(escapedInputPart2)

            const errors = blogFormDataValidation(req.body).errors;
            return res.render("addBlogPost", {errors:  errors , csrfToken:req.session.csrfToken, doubleSubmitCookie: req.session.doubleSubmitCookie});
        }else{*/

            //const escapedReqBody = escapeAllInput(req.body)
            const blogTitle = req.body.blogTitle
            const  blogData  = req.body.blogData
            const blogDescription = req.body.blogDescription
            const timeCreated = Date.now().toString();
            const dateCreated = new Date(parseInt(timeCreated)).toISOString().slice(0, 10);
            const author = req.session.usermail;
            const userIDQuery={
                text: 'SELECT id FROM users WHERE email = $1',
                values: [author],  // 24 hours in milliseconds
            }
            writeOnlyPool.query(userIDQuery).then((results)=>{
                let user_id = results.rows[0].id
                //console.log(user_id)
                const insertQuery = {
                    text: 'INSERT INTO blogdata (blogtitle, bloginfo, datecreated, blogDescription, blogauthor, user_id) VALUES ($1, $2, $3, $4, $5, $6)',
                    values: [blogTitle, blogData, dateCreated, blogDescription, author,user_id]
                };

                pool.query(insertQuery)
                    .then((results)=>{
                        console.log(results.rows)
                        res.redirect('/blogDashboard')})
                    .catch(err=>{
                        console.log(err)
                        res.render('addBlogPost', {errors: 'There was an error with adding the blog post', csrfToken:req.session.csrfToken, doubleSubmitCookie: req.session.doubleSubmitCookie})
                    })
            }).catch(err=>{
                console.log(err)
                res.render('addBlogPost', {errors: 'There was an error with adding the blog post',csrfToken:req.session.csrfToken, doubleSubmitCookie: req.session.doubleSubmitCookie })
            })
            console.log(blogTitle);
            console.log(blogData);

    }else{
        res.redirect('/')

    }

})


