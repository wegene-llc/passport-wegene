/**
 * Module dependencies.
 */
var util = require('util'),
  OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
  InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Wegene authentication strategy authenticates requests by delegating to
 * Wegene using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Wegene application's app key
 *   - `clientSecret`  your Wegene application's app secret
 *   - `callbackURL`   URL to which Wegene will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new WegeneStrategy({
 *         clientID: 'app key',
 *         clientSecret: 'app secret'
 *         callbackURL: 'https://www.example.net/auth/wegene/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

function Strategy(options, verify) {

  options = options || {};
  options.authorizationURL = options.authorizationURL ||
    'https://api.wegene.com/authorize/';
  options.tokenURL = options.tokenURL || 'https://api.wegene.com/token/';
  options.response_type = options.response_type || 'code';
  options.scopeSeparator = options.scopeSeparator || ' ';
  options.scope = options.scope || ['basic', 'email'];
  if(options.scope.indexOf('basic') === -1){
    options.scope.push('basic');
  }
  if(options.scope.indexOf('email') === -1){
    options.scope.push('email');
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'Wegene';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Wegene.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `Wegene`
 *   - `id`               Wegene userid
 *   - `email`            Wegene email
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
  var oauth2 = this._oauth2;
  oauth2.useAuthorizationHeaderforGET(true);
  oauth2.get('https://api.wegene.com/user/',
    accessToken, function (err, result) {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }

    result = JSON.parse(result);

    var profile = {
      provider: 'Wegene'
    };
    profile.id = result.id;
    profile.email = result.email;

    done(null, profile);
  });
};

/**
 * Return extra parameters to be included in the token request.
 *
 * In the case of Wegene OAuth process, an extra 'scope' parameter
 * is needed. And it has to be the same to the one used for requesting
 * authorization code
 *
 * @return {Object}
 * @api protected
 */

Strategy.prototype.tokenParams = function(options){
  options = options || {};
  options.scope = this._scope.join(this._scopeSeparator);
  return options;
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy
