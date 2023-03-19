const express = require('express');
require('dotenv').config({path:'info.env'});
const https = require('https');
const bodyParser = require('body-parser');
const fs = require('fs');
const ejs = require('ejs');


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
    app,signUpValidation, escapeAllInput, userExistsCheck
};
/*All functions used*/

//Sign up validation function:
function signUpValidation(reqBody){
    const errors = [];
   // const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    const passwordRegex = /(?=.{8,}$)(?=.*[a-zA-Z0-9]).*/
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    const usernameRegex= /^[a-z0-9]+$/i;

    for (const inputName in reqBody) {
        const input = reqBody[inputName];
        if(!input ||input.length < 1 ||(inputName==="username" && !usernameRegex.test(input)) ||(inputName==="password" && !passwordRegex.test(input))
            || (inputName ==="email" && !emailRegex.test(input))
        ){
            errors.push(`There is an error in the "${inputName}" input`);
            console.log(`There is an error in the "${inputName}" input`)
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
                console.log(result.rows[0])
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
                reject("There was an error during the sign-up process. Please refresh and try again");
            });
    });
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






/*All the application post routes*/
app.post('/sign-up', (req,res)=>{
    if(signUpValidation(req.body).isValid){

        const escapedReqBody = escapeAllInput(req.body)
        const email = escapedReqBody.email;
        const password = escapedReqBody.password;
        const username = escapedReqBody.username;
        //Check if the user already exists in the system:

        userExistsCheck(email).then((userExists) => {
            if (userExists) {
                //console.log(res.toString())
                //Redirect the user to the email verification page in order to prevent account enumeration, but no actual email will be sent to that user
                //since the user already exists in the system.
                res.render('email-verification', {email:email})

                // do something
            } else {
                //If user does not already exists in the password then we can hash the password
                console.log("User does not exist");
            }
        });


    }else{
        res.render('sign-up', {errors: "There is an error with your input value", message: false})

    }
})