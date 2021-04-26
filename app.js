const express = require("express");
const app = express();
const cors = require("cors");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const port = process.env.PORT || 8001;

const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "nibss"
});

db.connect=(error)=>{
    if(error){
       console.log(error)
    }else{
        console.log("Database Connected!");
    }
}

/*................verify token...............*/
const verifyJWT = (req, res, next) =>{
    const token = req.headers["authorization"];
    if(!accessToken){ 
        res.send("token needed");
    }
    else {
        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded)=>{
            if (err){
                res.json({auth: false, message: "failed"})
            } else {
                req.userId = decoded.id;
                next();
            }
        })
    }
}

app.get("/loginAuth", verifyJWT, (req, res)=>{
    res.send("You're authenticated");
})
 

//middleware  
app.use(cors());

// Parsers to POST data
app.use(express.json({limit: '20mb'}));
app.use(express.urlencoded({ extended: false, limit: '20mb' }));




//APIs
/*................POST guest info into guestinfo table...............*/
app.post("/addguestinfo", (req, res) => {

    const {name, mobile, company, email, laptop, laptopserialnumber, host, purpose,appointment, picture} = req.body;

    const sqlInsert = "INSERT INTO guestinfo (name,mobile,company,email,laptop,laptopserialnumber,host,purpose,appointment,picture) VALUES (?,?,?,?,?,?,?,?,?,?)";
    db.query(sqlInsert, [name,mobile,company,email,laptop,laptopserialnumber,host,purpose,appointment,picture], (err, result) => {
        if(!err){
           res.status(200).send({message: "info added"});
       }else{
        console.log(err);
    } 
    });
})

/*................GET all guest info from guestinfo table...............*/
app.get("/getguestinfo", (req, res) => {

    const params = req.body;
    db.query("SELECT * FROM guestinfo", params, (err, result) => {
        if(!err){
           res.send(result)
        }else{
           console.log(err);
        }
    });
})

/*................POST returning guest info into guestlogs table...............*/
app.post("/returningguest", (req, res) => {

    const params = req.body;
    db.query("INSERT INTO guestlogs SET ?", params, (err, result) => {
       if(!err){
           res.send("info added");
       }else{
        console.log(err);
       }
    });
})

/*................GET returning guest info BY MOBILE_NO from guestlogs table...............*/
app.get("/returningguest/", (req, res) => {

    const mobile = req.body.mobile;
    db.query("SELECT * FROM guestlogs WHERE mobile = ?", mobile, (err, result) => {
       if(result.length > 0) {
           res.send(result);
        } 
       else{
           res.send("mobile number doesn't exist");
           console.log(err);
        }
    });
})

/*................Register new guest...............*/
app.post("/register", (req, res) => {

    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
    const hash = bcrypt.hashSync(password, 8);

    const sqlInsert = "INSERT INTO newguest (name,email,password) VALUES (?,?,?)"; 
    db.query(sqlInsert,[name, email, hash], (err, result) => {
        if(!err){
           res.status(200).send({message: "new guest created"});
       }else{
        console.log(err);
    } 
    });
})

/*................Login guest...............*/
app.get("/login", verifyJWT ,(req, res)=>{
    if(req.session.user){
        res.send({ loggedIn: true, user: req.session.user })
    }else{
        res.send({ loggedIn: false})
    }
});

/*................Login guest...............*/
app.post("/login", (req, res) => {

    const email = req.body.email;
    const password = req.body.password;

    db.query("SELECT * FROM newguest WHERE email = ?", email, (err, result)=>{
        if(err){
            res.send({
                err:err
            })
        }
        console.log(err);
        
        if(result.length > 0){
            bcrypt.compareSync(password, result[0].password, (err, response) => {
                if(response){
                    res.status(200).send({message: "Auth Success"})
                    //create token based on id
                    const id = { id: email }
                    const accessToken = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, {
                        espiresIn:6000,
                    })
                    // req.session.user = result;
                    res.json({
                        auth: true, 
                        accessToken: accessToken, 
                    });
                }else{
                    res.json({
                        auth: false, 
                        message: "incorrect password" 
                    });
                }
            })
        }else{
            res.json({
                auth: false, 
                message:"user doesn't exist"
            });
        }
    })
})


/* ..............Server Setup.............. */
app.listen(port, ()=>{
    console.log("running on port 8001");
}); 


