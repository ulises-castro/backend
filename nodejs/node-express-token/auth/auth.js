const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const UserModel = require('../model/model');

passport.use('signup', new localStrategy({
  usernameField: 'email',
  passwordField: 'password',
}, async (email, password, done) => {
  try {
    const user = await UserModel.create({ email, password });
    return done(null, user);
  } catch (error) {
    done(error);
  }
}));

passport.use('login', new localStrategy({
  usernameField: 'email',
  passwordField: 'password',
}, async (email, password, done) => {
  try {
    const user = await UserModel.findOne({ email });
    if( !user ) {
      return done(null, false, { message: 'User not found'});
    }

    const validate = await user.isValidPassword(password);
    if( !validate ) {
      return done(null, false, { message: 'Wrong password'});
    }

    return done(null, user, { message: 'Logged in Sucessfully'});
  } catch (error) {
    done(error);
  }
}));

const JWTstrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;

passport.use(new JWTstrategy({

  secretOrKey : 'top_secret',

  jwtFromRequest : ExtractJWT.fromUrlQueryParameter('secret_token')

}, async (token, done) => {
  try {
    return done(null, token.user);    
  } catch (error) {
    done(error);
  }
}));