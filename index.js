// https://github.com/arjaymarinas/node-practice.git

import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import pg from "pg";
import session from "express-session";

const app = express();
const port = 3000;

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

    const { username, password } = req.body;

    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]); 
        const user = result.rows[0];

        if(user){
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (passwordMatch) {

                req.session.user = user;
                res.redirect("/dashboard");
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

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});