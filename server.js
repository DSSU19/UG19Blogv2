const express = require('express');
require('dotenv').config({path:'info.env'});
const https = require('https');
const bodyParser = require('body-parser');
const nodemailer = require("nodemailer");
const fs = require('fs');
const ejs = require('ejs');
const crypto = require('crypto');


const app = express();
// Middleware and server set up
app.use(bodyParser.urlencoded({ extended: false }));
app.set('view engine', 'ejs');
app.set('views', 'views');
const port = 8080;

app.use(express.static('client'));
// Body parser middleware
app.use(bodyParser.json());
//Force input to be encoded correctly.
app.use(bodyParser.urlencoded({ extended: true }));


//Pg client information to enable queries from the database blog.
const { Pool, result } = require('pg');
//Switches the database name based on whether we are testing or using the actual application
const databaseName = process.env.NODE_ENV === "test" ? process.env.testDatabase : process.env.database;

const pool = new Pool({
    host: process.env.localhost,
    port: process.env.port,
    user: process.env.user,
    database: databaseName,
    password:  process.env.password,
});

//Transporter for sending emails:
// create reusable transporter object using the default SMTP transport
let transporter = nodemailer.createTransport({
    host: process.env.email_host,
    port: process.env.email_port,
    secure: process.env.email_secure, // true for 465, false for other ports
    auth: {
        user: process.env.email_user, // generated ethereal user
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
    app,signUpValidation, escapeAllInput, userExistsCheck, storePasswordInfo,
};
/*All functions used*/

//Sign up validation function:
function signUpValidation(reqBody){

    const errorMessages = {
        username: "Username must be alphanumeric",
        password: "Password must be at least 8 characters long",
        email: "Please enter a valid email address",
        passwordConfirmation: "Passwords do not match."
    };
    const errors = [];
   // const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    const passwordRegex = /(?=.{8,}$)(?=.*[a-zA-Z0-9]).*/
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const usernameRegex= /^[a-z0-9]+$/i;
    for (const inputName in reqBody) {
        const input = reqBody[inputName];
        if(!input ||input.length < 1 ||(inputName==="username" && !usernameRegex.test(input)) ||(inputName==="password" && !passwordRegex.test(input))
            || (inputName ==="email" && !emailRegex.test(input)) || (inputName==="passwordConfirmation") && input !== reqBody["password"]
        ){
            errors.push(errorMessages[inputName]);
            //console.log(errorMessages[inputName]);
            //errors.push(`There is an error in the "${inputName}" input`);
            //console.log(`There is an error in the "${inputName}" input`)
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

//function to check if the  user already exists (must be a verified user)
 function userExistsCheck(email){
    return new Promise((resolve, reject) => {
        //console.log('Exists function is executed');
        const userSelectQuery = {
            text: 'SELECT * FROM users WHERE email = $1 AND isverified = $2',
            values: [email, true] // 24 hours in milliseconds
        };
        pool.query(userSelectQuery)
            .then((result) => {
                //console.log(result.rows[0])
                if (result.rows.length > 0) {
                    //console.log("User exists");
                    resolve(true);
                } else {
                    console.log("User does not exist");
                    resolve(false);
                }
            })
            .catch((err) => {
                console.log("The error is:" + err)
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
            console.log("user does not exist");
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
            console.log('Data saved successfully!');
            return true;
        } else {
            console.log(err);
            return false;
        }
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
        const saltedAndPepperPassword = password + salt+pepper;
        const hashedPassword = crypto.createHash('sha256').update(saltedAndPepperPassword).digest('hex');
        return hashedPassword
    }else{
        return false
    }
}

async function sendVerificationEmail(email, token,res) {
    // Construct the verification link
    const verificationLink = `https://localhost:8080/verify?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;
    // send mail with defined transport object
    // Construct the email message
    const message = await transporter.sendMail({
        from: 'webabenablogtest@gmail.com',
        to: email,
        subject: 'Verify your email address',
        text: `Please click the following link to verify your email address: ${verificationLink}`,
        html: `Please click <a href="${verificationLink}">here</a> to verify your email address.`
    });
    console.log("Message sent: %s", message.messageId);
    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
    // Preview only available when sending through an Ethereal account
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(message));
    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
    return res.render("email-verification", { email: email});
}







//Validation input functions
 function validateAlphaNumeric(reqBody){
    const errors = [];
   // const regex = /^[a-zA-Z,.!?'"()\s]+$/; // regular expression to match letters and punctuations
     const regex= /^[a-z0-9]+$/i
    for (const inputName in reqBody) {
        const input = reqBody[inputName];
        console.log("Length is " + input.length)
        console.log("The input is: " + input);
        if (!regex.test(input) || !input || input.length < 1 || (inputName==="password" && input.length <= 8)) {
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

/*All the application get routes*/
//Routes
app.get('/', (req, res) => {
    res.render('index', {errors: false, message: false})
});

app.get('/sign-up', (req, res) => {
    res.render('sign-up', {errors: false, message: false})
});


app.get('/email-verification', (req,res)=>{
    res.render('email-verification', {email: email})
})
app.get('/verify', async (req, res) => {
    //console.log('this got triggered')
    // Extract the email and token from the URL query string
    const email = req.query.email;
    const token = req.query.token;
    const currentTime = Date.now()
    //this value is for testing
    //const timeDifference = 5 * 60 * 1000;
    const timeDifference = 24 * 60 * 60 * 1000;
    //Check if the token in the link is correct as the one in the database
    const tokenQuery = {
        text: 'SELECT verificationtoken FROM users WHERE email = $1 AND $2 - creationtime < $3',
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
                        res.render('index', {message: 'Your account has been verified', errors: false})
                    }).catch(err=>console.log(err));
            }else{
                return res.render('verificationError')
            }
        }
    })
})






/*All the application post routes*/
app.post('/sign-up',  (req,res)=>{


    if(signUpValidation(req.body).isValid){

        const escapedReqBody = escapeAllInput(req.body)
        const email = escapedReqBody.email;
        const password = escapedReqBody.password;
        const passwordConfirmation =escapedReqBody.passwordConfirmation;
        const username = escapedReqBody.username;
        //Check if the user already exists in the system:

        userExistsCheck(email).then(async (userExists) => {
            if (userExists) {
                //console.log(res.toString())
                //Redirect the user to the email verification page in order to prevent account enumeration, but no actual email will be sent to that user
                //since the user already exists in the system.
                res.render('email-verification', {email:email})
            } else {
                //If user does not already exists in the password then we can hash the password
                //Call the hashedPassword which is a function that generated a random hash.
                const hashedPassword =  await hashPassword(password, email)
                console.log(hashedPassword)
                if(hashedPassword){
                    //Process with hashed Password has gone well without any errors and thus process can continue.
                    // Generate a unique verification token for email verification
                   const token = crypto.randomBytes(20).toString('hex');
                   const creationTime = Date.now();
                   // Insert the new user into the "users" table
                   const query = {
                       text: 'INSERT INTO users (email, password, isverified, verificationtoken, firstname, creationtime) VALUES ($1, $2, $3, $4, $5, $6)',
                       values: [email, hashedPassword, false, token, username, creationTime]
                   };
                   pool.query(query)
                       .then(() => sendVerificationEmail(email, token,res))
                       .catch(err=>console.error(err))
                }else{
                    console.log("Password unsuccessfully hashed");
                    res.render('sign-up', {errors: "There was an error during the sign-up process, please try again later", message: false})
                }
            }
            });
    }else{
        const errors = signUpValidation(req.body).errors;
        res.render('sign-up', {errors: errors, message: false})

    }
})