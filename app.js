//jshint esversion:6

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const passport = require("passport");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.set("view engine","ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret: process.env.myLongSecret,
  resave:false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.mongoUrl,
{
  useNewUrlParser:true,
  useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  twitterId:String,
  username:String,
  secret: String
});

userSchema.plugin(passportLocalMongoose, {usernameUnique: false});
userSchema.plugin(findOrCreate);


const User = mongoose.model("user",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id,username:profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new TwitterStrategy({
    consumerKey: process.env.TWITTER_CONSUMER_KEY,
    consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
    callbackURL: "http://localhost:3000/auth/twitter/secrets"
  },
  function(token, tokenSecret, profile, cb) {

    User.findOrCreate({twitterId: profile.id, username:profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));

//passport code copy pasted from docs

app.get('/auth/twitter',
  passport.authenticate('twitter'));

app.get('/auth/twitter/secrets',
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/",(req,res)=>{
  res.render("home");
});

app.get("/login",(req,res)=>{
  res.render("login");
});

app.get("/register",(req,res)=>{
  res.render("register");
});

app.get("/secrets",(req,res)=>{
  User.find({"secret":{$ne:null}},(err,result)=>{ //not equall to null
    if(err){
      console.log(err);
    } else {
      if(result){
        res.render("secrets",{userData:result})
      }
    }
  });
});

app.get("/submit",(req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit",(req,res)=>{
  User.findById(req.user.id,(err,foundUser)=>{
    if(err){
      console.log(err);
    } else {
      if(foundUser){
        foundUser.secret = req.body.secret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.post("/register",(req,res)=>{

  User.register({username:req.body.username}, req.body.password,(err,user)=>{
    if(err){
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req,res,()=>{
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login",(req,res)=>{

  const newObj = new User({
    username:req.body.username,
    password: req.body.password
  });

  req.login(newObj,(err)=>{
    if(err){
      console.log(err);
    } else {
      passport.authenticate("local")(req,res,()=>{
        res.redirect("/secrets");
      });
    }
  });

});

app.get("/logout",(req,res)=>{
  req.logout();
  res.redirect("/");
});

app.listen(process.env.PORT || 3000,()=>{
  console.log("server running");
});



// Bcrypt login///////////////////////////////////////////////

// User.findOne({email:req.body.username},(err,foundUserObj)=>{
//   if(!err){
//     if(foundUserObj){
//       bcrypt.compare(req.body.password,foundUserObj.password, function(error, result) {
//         if(result==true){
//           res.render("secrets");
//         }  else {
//           console.log(error);
//         }
//        });
//
//     }
//   } else {
//     console.log(err);
//   }
// });

// Bcrypt Registeration///////////////////////////////////////////

// bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//   const newUser = new User({
//     email:req.body.username,
//     password: hash
//   });
//
//   newUser.save((err)=>{
//     if(!err){
//       res.render("secrets");
//     } else {
//       console.log(err);
//     }
//   });
// });


//Encryption with Mngoose-encryption/////////////////////////////////////////////////////
//userSchema.plugin(encrypt,{secret:process.env.secretKey,encryptedFields:["password"] });
