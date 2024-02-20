// https://github.com/arjaymarinas/node-practice.git

import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import pg from "pg";
import session from "express-session";
import cookieParser from "cookie-parser";
import nodemailer from "nodemailer";
import crypto from "crypto";

const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: 'My!S3cr3t&K3y',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 * 7 } // 1 week
}));

app.use(session({
    secret: 'My!S3cr3t&K3y', // This is an example secret key
    resave: false,
    saveUninitialized: false
}));

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "post-practice",
    password: "Ghost0153",
    port: "5432"
});

db.connect();

app.use(express.static("public"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended : true }));

app.get("/", (req, res) => {
    res.render("index.ejs");
});

app.post("/login", async (req, res) => {

    const { username, password, remember } = req.body;

    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]); 
        const user = result.rows[0];

        if(user){
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {

                if (remember) {
                    res.cookie('rememberMe', 'true', { maxAge: 1000 * 60 * 60 * 24 * 7 }); // 1 week
                } else {
                    res.clearCookie('rememberMe');
                }

                req.session.user = user;
                //res.redirect("/dashboard");
                res.status(200).send("Successfully logged in.");
                console.log("Successfully logged in.");

            } else {
                res.status(401).send('Invalid username or password');
            }
        }else {
            res.status(401).send('User not found');
        }

    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).send('Internal server error');
    }

});

app.get("/dashboard", (req, res) => {
    const user = req.session.user;
    res.render("dashboard.ejs", {user : user});
});

app.get("/recover-account", (req, res) => {
    res.render("recover-account.ejs");
});

app.post("/account/forgot-password", async (req, res) => {
    const username = req.body.username;
    const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = result.rows[0];

    if(result.rows.length === 0){
        return res.status(404).send("User not found.");
    }

    const token = crypto.randomBytes(20).toString('hex');
    const expiration = new Date(Date.now() + 15 * 60 * 1000);

    await db.query("INSERT INTO tokens (username, token, expiration, type) VALUES ($1, $2, $3, 'password_reset')", [username, token, expiration]);

    const resetLink = `http://localhost:3000/account/forgot-password?userId=${username}&token${token}`;
    let subject = "Password reset";
    let message = "Click the following link to reset your password: ";

    sendEmail(user.email, resetLink, subject, message);

    res.status(200).send("Password reset email sent. " + token);
});

app.post("/account/forgot-password/changePassword", async (req, res) => {

    const {username, token, password} = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query("UPDATE users SET password = $1 WHERE username = $2", [hashedPassword, username]);
    await db.query('DELETE FROM tokens WHERE token = $1', [token]);

    return res.status(200).send("Password successfully updated.");

});

app.get("/account/forgot-password/", async (req, res) => {
    //res.send(req.params);
    const {username, token} = req.query;
    const result = await db.query("SELECT username, expiration FROM tokens WHERE token = $1", [token]);
    const user = result.rows[0];

    if(result.rows.length === 0){
        return res.status(404).send("Invalid or expired token");
    }

    const expiration = new Date(user.expiration);

    if(expiration < new Date()){
        return res.status(401).send("Token has expired.");
    }else{
        return res.status(200).send("Token not expired.");
    }

});

app.post("/create-account", async (req, res) => {
    const {firstName, lastName, username, password, email} = req.body;

    const registrationToken = crypto.randomBytes(20).toString('hex');
    const registrationLink = `http://localhost:3000/account/verify?userId=${username}&token=${registrationToken}`;
    const expiration = new Date(Date.now() + 15 * 60 * 1000); // 15 mins

    try {
        await db.query("INSERT INTO users (first_name, last_name, username, password, email, is_verified) VALUES ($1, $2, $3, $4, $5, 0)", [firstName, lastName, username, password, email]);
        await db.query("INSERT INTO tokens (username, token, expiration, type) VALUES ($1, $2, $3, 'account_verify')", [username, registrationToken, expiration]);

        let subject = "Verify your registration";
        let message = "Click the following link to verify your acccount: ";

        sendEmail(email, registrationLink, subject, message);
        res.status(200).send("Registration successfully submitted. Please verify your account using the link sent to your email.");
    } catch (error) {
        console.log("Error inserting data: ", error);
        res.status(500).json({ message : "Internal server error." });   
    }
});

app.get("/account/verify", async (req, res) => {
    const {username, token} = req.query;
    try {
        const result = await db.query("SELECT username, expiration FROM tokens WHERE token = $1", [token]);
        const count = result.rows.length;
        const row = result.rows[0];

        if(count === 0){
            return res.status(404).send("Invalid or expired link.");
        }

        const expiration = row.expiration;

        if(expiration < new Date()){
            return res.status(401).send("Link is already expired.");
        }
        
        await db.query("UPDATE users SET is_verified = 1 WHERE username = $1", [username]);
        await db.query("DELETE FROM tokens WHERE token = $1", [token]);

        res.status(200).send("Successully verified.");

    } catch (error) {
        res.status(500).send();
    }
});

function sendEmail(email, resetLink, subject, message) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      auth: {
        user: '',
        pass: '',
      },
    });
  
    const mailOptions = {
      from: 'icttech@mcnp.edu.ph',
      to: email,
      subject: subject,
      text: message + " " + resetLink,
    };
  
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error(error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });
}   

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
