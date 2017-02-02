const passport = require('passport')
const User = require('../models/user')
const config = require('../config')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const LocalStrategy = require('passport-local')

// Create local Strategy
const localOptions = { usernameField: 'email'}
const localLogin = new LocalStrategy(localOptions, (email, password, done) => {
  // Verify this email and password, call done with the user
  // if it is the correct email and password
  // otherwise, call done wirh false
  User.findOne({ email: email}, (err, user) => {
    if (err) { return done(err) }
    if (!user) { return done(null, false) }

    // Compare passwords
    user.comparePassword(password, (err, isMatch) => {
      if (err) { return done(err) }
      if (!isMatch) { return done(null, false) }

      return done(null, user)
    })
  })
})

// Setup options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
}

// Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
  // See if the user ID in the payload exist in the database
  // If it does, call 'done' with that other
  // otherwise, call done with user object
  User.findById(payload.sub, (err, user) => {
    if (err) { return done(err, false) }

    if (user) {
      done(null, user)
    } else {
      done(null, false)
    }
  })
})

// Tell passport to use this strategy
passport.use(jwtLogin)
passport.use(localLogin)
