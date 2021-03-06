const express = require('express');
const cors = require('cors'); //for security cross origin
const passport = require('passport');//for entire auth library
const passportLocal = require('passport-local').Strategy; //for strategy
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs'); // for hashing the passport
const session = require('express-session');
const bodyParser = require('body-parser');
const dotEnv = require('dotenv');
dotEnv.config();
const app = express();
const User = require('./user_model');
require('./db');

//middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(cors({
    origin: process.env.CLIENT_URL, // <- location of the react app were connecting to
    credentials: true //true!
}))
app.use(session({
    secret: process.env.SECRET_KEY,
    resave: true,
    saveUninitialized: true
}));
app.use(cookieParser(process.env.SECRET_KEY))  //session과 같은 secret code
app.use(passport.initialize());
app.use(passport.session());
require('./passportConfig')(passport);

// END OF MIDDLEWARE


//Routes
app.post("/register", (req, res) => {
    User.findOne({username: req.body.username}, async(err, doc) => {
        if(err) throw err;
        if(doc) res.send('User already exist');
        if(!doc){
            const hashedPassword = await bcrypt.hash(req.body.password, 10);
            const newUser = new User({
                username: req.body.username,
                password: hashedPassword,
            });
            await newUser.save();
            res.send('User Created')
        }
    })
})

app.post("/login", (req, res,next) => {
                            //local: id,password로 하는 전통적인 인증방식.
    passport.authenticate('local', (err,user,info) => {
        if(err) throw err;
        if(!user) res.send('No user exists');
        else{
            req.logIn(user, err => { //passport에서 req.logIn()이 존재.  // customCallback 사용시 req.logIn()메서드 필수
                if(err) throw err;
                res.send('Successfully authenticated');
                console.log(req.user); //login이 완료되면 req.user로 접근이 가능해진다.
            })
        }
    })(req, res, next);
})

app.get("/user", (req, res) => {
    res.send(req.user); //The user is stored in the req.user
})


//Start server
app.listen(process.env.PORT, () => {
    console.log('Server Has Started')
})
