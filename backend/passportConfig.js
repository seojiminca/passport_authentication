//for passport. we can authenticate a user using this.
const userModel = require('./user_model');
const bcrypt = require('bcryptjs') //unhash password
const localStrategy = require('passport-local').Strategy;

//to use the same instance throughout the app.
module.exports = passport => {
    passport.use(
        new localStrategy((username, password, done) => {
            userModel
                .findOne({username}, (err, user) => {
                    if (err) throw err;
                    if (!user) return done(null, false);//null is error. false is user
                    bcrypt.compare(password, user.password, (err, result) => {
                        if (err) throw err;
                        if (result === true) {
                            return done(null, user);
                        } else {
                            return done(null, false)
                        }
                    });
                })
        })
    )

    //passport require serializeUser and deserializeUser
    //serializeUser stores a cookie inside of the browser
    passport.serializeUser((user, cb) => {
        cb(null, user.id); //create a cookie with the user ID
    })
    passport.deserializeUser((id, cb) => {
        userModel.findById(id, (err, user) => {
            cb(err, user);
        })
    })
};
