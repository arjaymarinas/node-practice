// https://github.com/arjaymarinas/node-practice.git

import express from "express";
import bodyParser from "body-parser";

const app = express();
const port = 3000;

app.use(express.static("public"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended : true }));

app.get("/", (req, res) => {

})


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
