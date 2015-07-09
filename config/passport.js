/**
 * Passport configuration file where you should configure all your strategies
 * @description :: Configuration file where you configure your passport authentication
 */

var extend = require('extend');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var JwtStrategy = require('passport-jwt').Strategy;
var LdapStrategy = require('passport-ldapauth').Strategy;

// TODO: make this more stable and properly parse profile data

/**
 * Configuration object for local strategy
 * @type {Object}
 * @private
 */
var LOCAL_STRATEGY_CONFIG = {
  usernameField: 'email',
  passwordField: 'password',
  passReqToCallback: true
};

/**
 * Configuration object for JWT strategy
 * @type {Object}
 * @private
 */
var JWT_STRATEGY_CONFIG = {
  secretOrKey: "53c5ec198c6f51575796da791e5350cd6362bb3c7953f7c259ac792b7a93265d",
  tokenBodyField: 'access_token',
  authScheme: 'Bearer',
  passReqToCallback: true
};

var LDAP_STRATEGY_CONFIG = {
  {
    server: {
        url: 'ldap://cloudit.ogangi.com:389',
        bindDn: 'cn=Manager,dc=ogangi,dc=com',
        bindCredentials: 'oganginew',
        searchBase: 'dc=ogangi,dc=com',
        searchFilter: 'uid={{username}},ou=employees,ou=people,dc=ogangi,dc=com',
        //searchFilter: 'uid={{username}},ou=customers,ou=people,dc=ogangi,dc=com',
    }
  }
}

/**
 * Triggers when user authenticates via local strategy
 * @param {Object} req Request object
 * @param {String} email Email from body field in request
 * @param {String} password Password from body field in request
 * @param {Function} next Callback
 * @private
 */
function _onLocalStrategyAuth(req, email, password, next) {
  User
    .findOne({email: email})
    .exec(function (error, user) {
      if (error) return next(error, false, {});

      if (!user) return next(null, false, {
        code: 'E_USER_NOT_FOUND',
        message: email + ' is not found'
      });

      // TODO: replace with new cipher service type
      if (!CipherService.create('bcrypt', user.password).compareSync(password)) return next(null, false, {
        code: 'E_WRONG_PASSWORD',
        message: 'Password is wrong'
      });

      return next(null, user, {});
    });
}

/**
 * Triggers when user authenticates via JWT strategy
 * @param {Object} req Request object
 * @param {Object} payload Decoded payload from JWT
 * @param {Function} next Callback
 * @private
 */
function _onJwtStrategyAuth(req, payload, next) {
  User
    .findOne({id: payload.id})
    .exec(function (error, user) {
      if (error) return next(error, false, {});
      if (!user) return next(null, false, {
        code: 'E_USER_NOT_FOUND',
        message: 'User with that JWT not found'
      });

      return next(null, user, {});
    });
}

function _onLdapStrategyAuth(req, user, next){
  if(!user) {
      return next(null, false, {message: 'Unknown user'});
  }
  User.findOne({username:user.uid}).exec(function(err,user) {
      if(err) {
          return next(err);
      }
      return next(null, user);
  });
}

passport.use(new LocalStrategy(extend({}, LOCAL_STRATEGY_CONFIG), _onLocalStrategyAuth));
passport.use(new JwtStrategy(extend({}, JWT_STRATEGY_CONFIG), _onJwtStrategyAuth));
passport.use(new LdapStrategy(extend({}, LOCAL_STRATEGY_CONFIG), _onLdapStrategyAuth));
