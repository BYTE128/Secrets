require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose  = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

const app = express();
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

//Below line used for passport-local-mongoose
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//console.log(process.env.SECRET + process.env.API_KEY);

//Do this step before creating the model, below step required for encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//Below two lines are for serializing a user locally i.e. works only for local strategy
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//Below written serialize and deserialize works for all strategies
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
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
}
));

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

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
passport.authenticate("google", { failureRedirect: "/login" }),
function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
}
);

app.get("/auth/facebook", 
passport.authenticate("facebook")
);

app.get("/auth/facebook/secrets",
passport.authenticate("facebook", { failureRedirect: "/login" }),
function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
}
);

app.get("/secrets", (req, res) => {
    User.find({ "secret": { $ne: null } }, { _id: 0, "secret": 1 }, (err, foundSecrets) => {
        if(err) {
            console.log(err);
        } else {
            res.render("secrets", { usersWithSecrets: foundSecrets });
        }
    });
});

app.get("/submit", (req, res) => {
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, (err, foundUser) => {
        if(err) {
            console.log(err);
        } else {
            if(foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(() => {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", (req, res) => {
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if(err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    
    req.login(user, (err) => {
        if(err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.get("/logout", (req, res) => {
    req.logout();
    req.session.destroy();
    res.redirect("/");
})

app.listen(3000, () => { console.log("Server running on port 3000"); });




//Bcrypt register post route
// app.post("/register", (req, res) => {
//     bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
//         newUser.save((err) => {
//             if(err) {
//                 console.log(err);
//             } else {
//                 res.render("secrets");
//             }
//         });
//     });
// });

//Bcrypt login post route
// app.post("/login", (req, res) => {
//     const username = req.body.username;
//     const password = req.body.password;
//     // const password = md5(req.body.password); //Hashing a password
//     User.findOne({ email: username }, (err, foundUser) => {
//         if(err){
//             console.log(err);
//         } else {
//             if(foundUser) {
//                 //Level 1 security
//                 // if(foundUser.password === password){
//                 //     res.render("secrets");
//                 // }

//                 bcrypt.compare(password, foundUser.password, (err, result) => {
//                     if(result) {
//                         res.render("secrets");
//                     }
//                 });
//             }
//         }
//     });
// });