const jwt = require('jwt-simple')
const User = require('../models/user')
const config = require('../config')

function tokenForUser(user) {
  const timestamp = new Date().getTime()
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret)
}

exports.signin = (req, res, next) => {
  // User has already had their email and password auth
  // We just need to give them a token
  res.send({ token: tokenForUser(req.user) })
}

exports.signup = (req, res, next) => {
  const email = req.body.email
  const password = req.body.password

  if (!email || !password) {
    return res.status(422).send({ error: 'You must provide an email and password' })
  }

  // See if user already exist on database
  User.findOne({ email: email }, (err, existingUser) => {
    if (err) { return next(err) }

    // If user with an email exist, throw an error
    if (existingUser) {
      return res.status(422).send({ error: 'Email is in use' })
    }

    // If user with this email don't exist, create and save user record
    const user = new User({
      email: email,
      password: password
    })

    user.save((err) => {
      if (err) { return next(err) }

      // Send response that our user is created
      res.json({ token: tokenForUser(user) })
    })

  })
}
