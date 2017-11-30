/**
 * Module dependencies.
 */
var passport = require('passport-strategy'),
	util = require('util');

/**
 * `Strategy` constructor.
 *
 * The custom authentication strategy authenticates requests based on a function callback.
 * Applications must supply a `verify` callback which executes custom authentication logic, and then calls the `done` callback supplying a `user`, which should be set to `false` if the credentials are not valid. If an exception occured, `err` should be set.
 *
 * Examples:
 *     passport.use(new CustomStrategy(
 *       options,
 *       function(req, done) {
 *         User.findOne({
 *           username: req.body.username
 *         }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Function} verify Verifies the user.
 * @api public
 */
function Strategy() {
	switch (arguments.length) {
		case 1:
  		this._authConfig = {};
			this._verify = arguments[0];
			break;
		case 2:
			this._authConfig = arguments[0];
			this._verify = arguments[1];
			break;
		default:
			throw new TypeError('CustomStrategy requires one (verify) or two (options, verify) arguments');
	}
	if (typeof this._verify !== 'function') {
		throw new TypeError('CustomStrategy requires a verify callback');
	}
	passport.Strategy.call(this);
	this.name = 'custom';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 * @param {Object} req HTTP request object.
 * @api protected
 */
Strategy.prototype.authenticate = function (req) {
	var self = this;

	function verified(err, user, info) {
		if (err) {
			return self.error(err);
		}
		if (!user) {
			return self.fail(info);
		}
		self.success(user, info);
	}

	try {
		this._verify(req, verified);
	} catch (ex) {
		return self.error(ex);
	}
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
