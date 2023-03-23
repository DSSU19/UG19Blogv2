const express = require('express');
require('dotenv').config({path:'info.env'});
const https = require('https');
const bodyParser = require('body-parser');
const nodemailer = require("nodemailer");
const fs = require('fs');
const ejs = require('ejs');
const crypto = require('crypto');
const session = require('express-session');
const { v4: uuid } = require('uuid')


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

app.use(session({
    secret: process.env.secret_key,
    genid: (req) => {
        return uuid(); // use UUIDs for session IDs
    },
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: true,
        httpOnly:true,
        maxAge: 24 * 60 * 60 * 1000, // 1 day
        sameSite: 'lax',
    }

}));


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
    app,signUpValidation, escapeAllInput, userExistsCheck, storePasswordInfo,loginValidation, getPasswordInfo, validateLoginCredentials, TwoFactorEmail, searchBarValidation, escapeInput,
    blogFormDataValidation
};
/*All functions used*/


/*Functions for the sign up functionality*/
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
        pool.query(userSelectQuery)
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
        const saltedAndPepperPassword = password + salt + pepper;
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



/*Login functions*/
//Login valid function
function loginValidation(reqBody){
    let isValid = true
    const passwordRegex = /(?=.{8,}$)(?=.*[a-zA-Z0-9]).*/
    const emailRegex = /^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,63})$/;
    for (const inputName in reqBody) {
        const input = reqBody[inputName];
        if(!input ||input.length < 1 ||(inputName==="password" && !passwordRegex.test(input))
            || (inputName ==="email" && !emailRegex.test(input)) || (inputName==="passwordConfirmation") && input !== reqBody["password"]
        ){
            isValid = false;
        }
    }
    return isValid;
}


//
async function getPasswordInfo(email) {
    try {
        const pepperFileName = process.env.NODE_ENV === "test" ? 'test/info/test_pepper.json': 'info/pepper.json';
        const saltFileName = process.env.NODE_ENV === "test" ? 'test/info/test_salt.json': 'info/salts.json';
        const saltData = await fs.promises.readFile(saltFileName, 'utf8');
        const saltObj = JSON.parse(saltData);
       // console.log(JSON.stringify(saltObj));
        const userSalt = saltObj.user_info.find(u => u.email === email);
        const pepperData = await fs.promises.readFile(pepperFileName, 'utf8');
        const pepperObj = JSON.parse(pepperData);
        //console.log(JSON.stringify(pepperObj));
        const userPepper= pepperObj.user_info.find(u => u.email === email);
        console.log("The pepper: " + JSON.stringify(userPepper))
        console.log("The salt: " + JSON.stringify(userSalt))
        if(userPepper && userSalt){
            //console.log('gets here')
            return {salt: userSalt.salt, pepper: userPepper.pepper};
        }else{
            return false;
        }
        //return userSalt ? userSalt.salt : null;
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
        const saltedAndPepperedPassword = password + passwordInfo.salt + passwordInfo.pepper;
        //console.log(saltedAndPepperedPassword)
        const hashedPassword = crypto.createHash('sha256').update(saltedAndPepperedPassword).digest('hex');
        console.log(hashedPassword)
        const userQuery = {
            text: 'SELECT email, password FROM users WHERE email = $1 AND password =$2 AND isverified =$3',
            values: [email, hashedPassword, true] // 24 hours in milliseconds
        };
        try {
            const result = await pool.query(userQuery);
            console.log(result.rows[0])
            if(result.rows.length > 0){
                return true;
            }else{
                return false;
            }
        } catch (error) {
            console.log(error);
            return false;
        }

    }else{
        return false;
    }
}

async function TwoFactorEmail(email, token,res) {
    // send mail with defined transport object
    // Construct the email message
    const message = await transporter.sendMail({
        from: 'webabenablogtest@gmail.com',
        to: email,
        subject: 'One Time PassCode',
        text: `This is your one time token: ${token}`,
        html: `This is your token: <b> ${token}</b>`
    });
    console.log("Message sent: %s", message.messageId);
    // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
    // Preview only available when sending through an Ethereal account
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(message));
    // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
    return res.render("verifyToken", { message: email, errors: false, email: email});
}





//Validation input functions
 function blogFormDataValidation(reqBody){
     const errorMessages = {
         blogTitle: "There is an invalid input in your blog title",
         blogDescription: "There is an invalid input in your blog description",
         blogData: "There is an invalid input in your blog data",

     };
     const errors = [];
     const regex = /^[a-zA-Z0-9\s\.\?\!\,\-]+$/g // regular expression to match letters and punctuations
    for (const inputName in reqBody) {
        const input = reqBody[inputName];
        console.log("The input is : " + input)
        //console.log("Length is " + input.length)
        //console.log("The input is: " + input);
        if (!regex.test(input) || !input || input.length < 1 ) {
            console.log("The error is in: "+ input)
            errors.push(errorMessages[inputName]);
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
    const regex = /^[a-zA-Z,.!?'"()\s]+$/; // regular expression to match letters and punctuations

    for (const inputName in reqBody) {
        const input = reqBody[inputName];
        console.log("Length is " + input.length)
        console.log("The input is: " + input);
        if (!regex.test(input) || !input || input.length < 1) {
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


// Create a middleware function to generate and store a CRF token
function generateCRSFToken(req, res, next) {
    // Generate a random token using crypto module
    // Store the token in the session variable
    req.session.token = crypto.randomBytes(32).toString('hex');
    console.log(req.session.token)
    // Pass the token to the next middleware function
    next();
}

function searchBarValidation(input){
    const searchRegex =  /^[a-zA-Z0-9\s]+$/;
    if(!searchRegex.test(input)){
        return false
    }else{
        return true;
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

/*Blog gets*/
app.get('/blogDashboard', (req, res)=>{
    if(!req.session.usermail){
        //Will be changed to contain name rather than email
        res.redirect('/')

    }else{
        //Get all the blog posts from the database:
        const getAllPostQuery = {
            text: 'SELECT * FROM blogdata ORDER BY datecreated ASC ',
        };
        pool.query(getAllPostQuery, (err, result)=>{
            if (err){
                console.error(err);
                res.render('blogDashboard', {firstname: req.session.firstname, errors: "There was an error retrieving the posts", post: '', usermail:req.session.usermail })

            }else{
                const blogPosts = result.rows;
                //console.log("The posts are " + blogPosts);
                res.render('blogDashboard', {firstname: req.session.firstname, errors: false, posts: blogPosts, usermail: req.session.usermail })
            }
        })

    }
})
app.get('/editblog/:id', (req, res)=>{
    if (req.session.usermail){
        const blogId = req.params.id;
        const getBlogPostQuery = {
            text: 'SELECT * FROM blogData WHERE id = $1',
            values: [blogId]
        };
        pool.query(getBlogPostQuery, (err, result)=>{
            if(err){
                res.render('editBlog', {errors: 'There was an error with updating the blog', post: '', firstname: req.session.firstname})
            }else{
                const blogPost = result.rows[0]
                res.render('editBlog', {errors: false, post: blogPost, firstname: req.session.firstname })
            }
        })

    }else{
        res.redirect('/login')

    }
})

app.get('/addBlogPost', generateCRSFToken, (req, res)=>{
    if(!req.session.usermail){
        //Will be changed to contain name rather than email
        res.redirect('/')
    }else{
        console.log(req.session.token)
        res.render('addBlogPost', {errors:false, csrfToken: req.session.token})

    }
})


app.get('/readblog/:id', (req, res) => {
    if(req.session.usermail){
        const blogId = req.params.id;
        const getBlogPostQuery = {
            text: 'SELECT * FROM blogData WHERE id = $1',
            values: [blogId]
        };
        pool.query(getBlogPostQuery, (err, result) => {
            if (err) {
                console.error(err);
                res.render('error', {errors: 'There was an error retrieving the blog post', firstname: req.session.firstname, post:'' });
            } else {
                const blogPost = result.rows[0];
                res.render('fullBlog', {post: blogPost, errors:false, firstname: req.session.firstname});
            }
        });
    }else{
        res.redirect('/login')
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
            pool.query(likeQuery, (err, result) => {
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
        res.redirect('/');
    }
});




/*All the application post routes*/
app.post('/sign-up',  (req,res)=>{
    if(signUpValidation(req.body).isValid){
        const escapedReqBody = escapeAllInput(req.body)
        const email = escapedReqBody.email;
        const password = escapedReqBody.password;
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

app.post('/login', async (req, res)=>{
    if(loginValidation(req.body)){
        const escapedLoginBody= escapeAllInput(req.body);
        const email = escapedLoginBody.email;
        const password = escapedLoginBody.password;
        const userValid = await validateLoginCredentials(password, email);
        if(userValid){
            const token=   Math.floor(100000 + Math.random() * 900000);
            let creationTime = Date.now();
            const selectQuery = {
                text: 'SELECT otp, used FROM otps WHERE email = $1',
                values: [email] // 24 hours in milliseconds
            };
            pool.query(selectQuery)
                .then((result)=>{
                    if(result.rows.length > 0){
                        const updateQuery = {
                            text: 'UPDATE otps SET used = $1, otp = $2, creationtime= $3 WHERE email = $4',
                            values: [false, token, creationTime, email]
                        };
                        pool.query(updateQuery);
                    }else{
                        //This means that there has been no otp set before
                        const query = {
                            text: 'INSERT INTO otps (email, otp, used, creationtime) VALUES ($1, $2, $3, $4)',
                            values: [email, token, false, creationTime]
                        };
                        pool.query(query)
                    }

                })
            //Two factor Authentication.
            await TwoFactorEmail(email, token, res)
        }else{
            res.render('index', {errors: "Username and/or password is incorrect", message: false})
        }
        console.log(email,password)

    }else{
        res.render('index', {errors: "Username and/or password is incorrect", message: false})
    }

})

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
                   //Validate the user
                   req.session.usermail = email;
                   //Get users name
                   pool.query(nameQuery)
                       .then((results)=>{
                           console.log(results.rows[0])
                           req.session.firstname= results.rows[0].firstname;
                           res.redirect('/blogDashboard');
                           pool.query(deleteTokenQuery)
                       })
               }else{
                   res.render('verifyToken', {errors:'Invalid token', email:email, message: email})
               }
           })

})

app.post('/logout', (req, res)=> {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
            res.status(500).send('Server Error');
        } else {
            res.clearCookie('connect.sid');
            res.redirect('/');
        }
    });
})





/*Blog post quotes*/
app.post('/deleteblog/:id', (req, res)=>{
    if(req.session.usermail){
        const id = req.params.id;
        const deletePostQuery = {
            text: 'DELETE FROM blogdata WHERE id = $1',
            values: [id] // 24 hours in milliseconds
        };

        pool.query(deletePostQuery, (err, results)=>{
            if(err){
                console.log(err)
                res.render('blogDashboard', {errors: 'Error deleting the blog post', firstname: req.session.usermail, post:'' })
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
                res.render('editBlog', {errors: 'There was an error with updating the blog', post: '', firstname: req.session.usermail})

            }else{
                const blogPost = result.rows[0]
                const blogTitle = escapeInput(req.body.blogtitle);
                const blogDescription = escapeInput(req.body.blogdescription);
                const blogInfo = escapeInput(req.body.bloginfo);
                //console.log(blogInfo, blogDescription, blogTitle)
                const timeCreated = Date.now().toString();
                const dateCreated = new Date(parseInt(timeCreated)).toISOString().slice(0, 10);
                //let allData = [blogTitle, blogDescription, blogInfo]
                let allData = { blogTitle: blogTitle, blogDescription:blogDescription , blogInfo: blogInfo };

                if(!validateInputsAll(allData)){
                    return res.render("editBlog", {errors: 'There is an error in your input', firstname: req.session.usermail, post:blogPost});
                }else{
                    const updateQuery = {
                        text: 'UPDATE blogData SET blogtitle = $1, bloginfo = $2, datecreated= $3, blogdescription = $4 WHERE id = $5',
                        values: [blogTitle, blogInfo, dateCreated, blogDescription, blogId]
                    };
                    pool.query(updateQuery).then((result)=>{
                        res.redirect('/blogDashboard')
                    }).catch((err)=>{
                        console.log(err)
                        return res.render("editBlog", {errors: 'There was an error when trying to edit your blog', firstname: req.session.usermail, post:blogPost});
                    })
                }
            }
        })
    }else{
        res.redirect('/')
    }
})


app.post('/addBlogPost', (req, res)=>{
    //const errors = validationResult(req);
    if(req.session.usermail){
        if(!blogFormDataValidation(req.body)) {
            //return res.render("addBlogPost", {errors: errors.array(), csrfToken:req.session.token});
            // console.log("There is an error somewhere here")
            return res.render("addBlogPost", {errors: 'There is an error in your input', csrfToken:req.session.token});
        }else{
            const escapedReqBody = escapeAllInput(req.body)
            const blogTitle = escapedReqBody.blogTitle
            const  blogData  = escapedReqBody.blogData
            const blogDescription = escapedReqBody.blogDescription
            const timeCreated = Date.now().toString();
            const dateCreated = new Date(parseInt(timeCreated)).toISOString().slice(0, 10);
            // Get the CRF token value from the request body
            const userToken = req.body.csrftokenvalue;
            // Get the CRF token value from the session variable
            const serverToken = req.session.token;
            const author = req.session.usermail;
            const userIDQuery={
                text: 'SELECT id FROM users WHERE email = $1',
                values: [author],  // 24 hours in milliseconds
            }

            pool.query(userIDQuery).then((results)=>{
                let user_id = results.rows[0].id
                console.log(user_id)
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
                        res.render('addBlogPost', {errors: 'There was an error with adding the blog post'})
                    })
            }).catch(err=>{
                console.log(err)
                res.render('addBlogPost', {errors: 'There was an error with adding the blog post',csrfToken:req.session.token })
            })
            console.log(blogTitle);
            console.log(blogData);
        }
    }else{
        res.redirect('/')

    }

})