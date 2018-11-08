var express = require('express')
  , passport = require('passport')
  , util = require('util')
  , SamlStrategy = require('passport-saml').Strategy
  , fs = require('fs')
  , morgan = require('morgan')
  , bodyParser = require('body-parser')
  , path = require('path')
  , session = require('express-session');
  
const app = express();
const http = require('http');
const server = http.createServer();
const BEGIN_CERTIFICATE = '-----BEGIN CERTIFICATE-----';
const END_CERTIFICATE = '-----END CERTIFICATE-----';
let cert = fs.readFileSync('onelogin.pem', 'utf-8').replace(BEGIN_CERTIFICATE, '')
cert = cert.replace(END_CERTIFICATE, '');

console.log('cert:', cert)
server.on('request', app);

var users = [
    { id: 1, givenName: 'bob', email: 'bob@example.com' }
  , { id: 2, givenName: 'joe', email: 'joe@example.com' }
];

function findByEmail(email, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.email === email) {
      return fn(null, user);
    }
  }
  return fn(null, null);
}


// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
passport.serializeUser(function(user, done) {
  done(null, user.email);
});

passport.deserializeUser(function(id, done) {
  findByEmail(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new SamlStrategy(
  {
    path: '/login/callback',
    entryPoint: 'https://nexweb-dev.onelogin.com/trust/saml2/http-redirect/slo/858328',
    issuer: 'https://app.onelogin.com/saml/metadata/c70d0dd3-c063-4018-9a58-3a6a89f29bc7',
    protocol: 'http://',
    cert: cert
  },
  function(profile, done) {
    console.log("Auth with", profile);
    if (!profile.email) {
      return done(new Error("No email found"), null);
    }
    // asynchronous verification, for effect...
    process.nextTick(function () {
      findByEmail(profile.email, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          // "Auto-registration"
          users.push(profile);
          return done(null, profile);
        }
        return done(null, user);
      })
    });
  }
));

// configure Express
// session
app.use(session({resave: false, saveUninitialized: true, secret: 'Hello-Swagger', 
   cookie: { secure: false, sameSite: true }
  }));

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(morgan('short'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));  
app.use(passport.initialize());
app.use(express.static(__dirname + 'public'));
// catch 404 and forward to error handler
app.use("/favicon.ico", express.static('public/favicon.ico')); 


app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

// Initiates an authentication request with OneLogin
// The user will be redirect to OneLogin and once authenticated
// they will be returned to the callback handler below
app.get('/login', passport.authenticate('saml', {
  successReturnToOrRedirect: "/"
}));


app.post('/login/callback',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

var port = process.env.PORT || 3000;
server.listen(port, ()=> {
  console.log('express http server listening on port:', port);
});

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}
