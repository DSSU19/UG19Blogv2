const express = require('express');
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

//This is to get the server running
const options = {
    key: fs.readFileSync('mydomain.local+3-key.pem'),
    cert: fs.readFileSync('mydomain.local+3.pem')
};
const server = https.createServer(options, app);
server.listen(port, () => {
    console.log('Server running at https://localhost:8080/');
});


/*All the application get routes*/
//Routes
app.get('/', (req, res) => {
    res.render('index')
});