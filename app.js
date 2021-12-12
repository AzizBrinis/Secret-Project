require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require('mongoose-findorcreate')
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;


// const bcrypt = require("bcrypt");

// const saltRounds = 10;
// // const md5 = require("md5")
// // const encrypt = require("mongoose-encryption");

const app = express();

mongoose.connect("mongodb://localhost:27017/userDB");

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended : true}));
app.use(express.static("public"));
app.use(session({
    secret : "Little Secret",
    resave : false,
    saveUninitialized : false
}));
app.use(passport.initialize());
app.use(passport.session());

const userSchema = new mongoose.Schema ({
    email : String,
    password : String,
    secret : [String],
    googleId : String,
    facebookId : String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// // userSchema.plugin(encrypt, {secret : process.env.CODE_ME,encryptedFields : ["password"]});

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });


  ////////////////////////////////////////////////////////////: Facebook :////////////////////////////////////////////////////////////////


  passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


////////////////////////////////////////////////////////////: Facebook :////////////////////////////////////////////////////////////////

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.route("/")
    .get((req,res) => {
        res.render("home")
    });

app.route("/secrets")
    .get((req,res) => {
        if(req.isAuthenticated()) {
            res.render("secrets",{toSend : req.user.secret})
        }else{
            res.render("login")
        }
    });

app.route("/login")
    .get((req,res) => {
        res.render("login")
    })
    // .post((req,res) => {
    //     User.findOne({ email : req.body.username},(err,data) => {
    //         if(!err) {
    //             if(data) {
    //                 bcrypt.compare(req.body.password,data.password,(err,result) => {
    //                     if(result) {
    //                         res.render("secrets")
    //                     }
    //                 })
    //                 // // if(data.password === req.body.password) {
    //                 //  //if(data.password === md5(req.body.password)) {
    //             }
    //         }
    //     })
    // });
    .post((req,res) => {
        const newUser = new User({
            username : req.body.username,
            password : req.body.password
        })

        req.login(newUser,(err) => {
            if(!err) {
                passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets")
                })
            }
        })
    })

app.route("/register")
    .get((req,res) => {
        res.render("register")
    })
    // .post((req,res) => {
    //     bcrypt.hash(req.body.password,saltRounds,(err,hash) => {
    //         const newUser = new User ({
    //             email : req.body.username,
    //             password : hash
    //             // // password : md5(req.body.password)
    //         })
    //         newUser.save(err => {
    //             if(!err) {
    //                 res.render("secrets")
    //             }
    //         })
    //     })
        
    // }

    // );
    .post((req,res) => {
        User.register({username : req.body.username} , req.body.password, (err,user) => {
            if(err) {
                console.log(err)
                res.redirect("/register")
            }else {
                passport.authenticate("local")(req,res,function(){
                    res.redirect("/secrets")
                })
            }
        })
    });

app.route("/submit")
    .get((req,res) => {
        res.render("submit")
    })
    .post((req,res) => {
        const secret = req.body.secret;
        User.findById(req.user._id,(err,foundUser) => {
            if(!err) {
                if(foundUser) {
                    foundUser.secret.push(secret)
                    foundUser.save(() => {
                        res.redirect("/secrets")
                    })
                }
            }
        })
    })


app.route("/logout")
    .get((req,res) => {
        req.logout()
        res.redirect("/")
    })


app.listen(3000, () => {
    console.log("Connected On Port 3000")
})