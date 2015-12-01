var tokenSecret = 'your unique secret';
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var express = require('express');
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var passport = require('passport');
var http  = require('http');
var fs    = require('fs');
var mime  = require('mime');
var cache = {};
var LocalStrategy = require('passport-local').Strategy;
var userSchema = new mongoose.Schema({
    fName: String, 
    lName: String,
    organization: String,
    email: { type: String, unique: true },
    password: String,
});

userSchema.pre('save', function (next) {
    var user = this;
    if (!user.isModified('password')) return next();
    bcrypt.genSalt(10, function (err, salt) {
        if (err) return next(err);
        bcrypt.hash(user.password, salt, function (err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});
userSchema.methods.comparePassword = function (candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};
var eventSchema = new mongoose.Schema({
    _id: Number,
    eventname: String,
    speaker: String,
    starttime: String,
    endtime: Date,
    description: [String],
    attendees: [{
        type: mongoose.Schema.Types.ObjectId, ref: 'User'
    }],
});
var User = mongoose.model('User', userSchema);
var event = mongoose.model('Event', eventSchema);
mongoose.connect('mongodb://nimda:Pa55w0rd@ds054288.mongolab.com:54288/nucp');
var app = express();

app.set('port', process.env.PORT || 3000);
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({ secret: 'keyboard cat' }));
app.use(passport.initialize());
app.use(passport.session());;
app.use(express.static(path.join(__dirname, 'public')));
app.use(function (req, res, next) {
    if (req.user) {
        res.cookie('user', JSON.stringify(req.user));
    }
    next();
});
app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
});
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});
passport.use(new LocalStrategy({
    usernameField: 'email'
}, function (email, password, done) {
    User.findOne({ email: email }, function (err, user) {
        if (err) return done(err);
        if (!user) return done(null, false);
        user.comparePassword(password, function (err, isMatch) {
            if (err) return done(err);
            if (isMatch) return done(null, user);
            return done(null, false);
        });
    });
}));
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) next();
    else res.send(401);
}
app.post('/api/login', passport.authenticate('local'), function (req, res) {
    res.cookie('user', JSON.stringify(req.user));
    res.send(req.user);
});
app.post('/api/register', function (req, res, next) {
    var user = new User({
        fName: req.body.fName,
        lName: req.body.lName,
        organization: req.body.organization,
        email: req.body.email,
        password: req.body.password
    });
    user.save(function (err) {
        if (err) return next(err);
        res.send(200);
    });
});
app.get('/api/logout', function (req, res, next) {
    req.logout();
    res.send(200);
});
app.get('/api/events', function (req, res, next) {
    var query = Show.find();
    if (req.query.genre) {
        query.where({ genre: req.query.genre });
    } else if (req.query.alphabet) {
        query.where({ name: new RegExp('^' + '[' + req.query.alphabet + ']', 'i') });
    } else {
        query.limit(12);
    }
    query.exec(function (err, shows) {
        if (err) return next(err);
        res.send(shows);
    });
});