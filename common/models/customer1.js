'use strict';
var g = require('../../lib/globalize');
var isEmail = require('isemail');
var loopback = require('../../lib/loopback');
var utils = require('../../lib/utils');
var path = require('path');
var qs = require('querystring');
var SALT_WORK_FACTOR = 10;
var crypto = require('crypto');
// bcrypt's max length is 72 bytes;
// See https://github.com/kelektiv/node.bcrypt.js/blob/45f498ef6dc6e8234e58e07834ce06a50ff16352/src/node_blf.h#L59
var MAX_PASSWORD_LENGTH = 72;
var bcrypt;
try {
  // Try the native module first
  bcrypt = require('bcrypt');
  // Browserify returns an empty object
  if (bcrypt && typeof bcrypt.compare !== 'function') {
    bcrypt = require('bcryptjs');
  }
} catch (err) {
  // Fall back to pure JS impl
  bcrypt = require('bcryptjs');
}

var DEFAULT_TTL = 1209600; // 2 weeks in seconds
var DEFAULT_RESET_PW_TTL = 15 * 60; // 15 mins in seconds
var DEFAULT_MAX_TTL = 31556926; // 1 year in seconds
var assert = require('assert');

var debug = require('debug')('loopback:customer');

module.exports = function(customer) {
  
  Customer.prototype.createAccessToken = function(ttl, options, cb) {
    if (cb === undefined && typeof options === 'function') {
      // createAccessToken(ttl, cb)
      cb = options;
      options = undefined;
    }

    cb = cb || utils.createPromiseCallback();

    let tokenData;
    if (typeof ttl !== 'object') {
      // createAccessToken(ttl[, options], cb)
      tokenData = {ttl};
    } else if (options) {
      // createAccessToken(data, options, cb)
      tokenData = ttl;
    } else {
      // createAccessToken(options, cb);
      tokenData = {};
    }

    var userSettings = this.constructor.settings;
    tokenData.ttl = Math.min(tokenData.ttl || userSettings.ttl, userSettings.maxTTL);
    this.accessTokens.create(tokenData, options, cb);
    return cb.promise;
  };

  function splitPrincipal(name, realmDelimiter) {
    var parts = [null, name];
    if (!realmDelimiter) {
      return parts;
    }
    var index = name.indexOf(realmDelimiter);
    if (index !== -1) {
      parts[0] = name.substring(0, index);
      parts[1] = name.substring(index + realmDelimiter.length);
    }
    return parts;
  }

  /**
   * Normalize the credentials
   * @param {Object} credentials The credential object
   * @param {Boolean} realmRequired
   * @param {String} realmDelimiter The realm delimiter, if not set, no realm is needed
   * @returns {Object} The normalized credential object
   */
  Customer.normalizeCredentials = function(credentials, realmRequired, realmDelimiter) {
    var query = {};
    credentials = credentials || {};
    if (!realmRequired) {
      if (credentials.email) {
        query.email = credentials.email;
      } else if (credentials.username) {
        query.username = credentials.username;
      }
    } else {
      if (credentials.realm) {
        query.realm = credentials.realm;
      }
      var parts;
      if (credentials.email) {
        parts = splitPrincipal(credentials.email, realmDelimiter);
        query.email = parts[1];
        if (parts[0]) {
          query.realm = parts[0];
        }
      } else if (credentials.username) {
        parts = splitPrincipal(credentials.username, realmDelimiter);
        query.username = parts[1];
        if (parts[0]) {
          query.realm = parts[0];
        }
      }
    }
    return query;
  };


  Customer.login = function(credentials, include, fn) {
    var self = this;
    if (typeof include === 'function') {
      fn = include;
      include = undefined;
    }

    fn = fn || utils.createPromiseCallback();

    include = (include || '');
    if (Array.isArray(include)) {
      include = include.map(function(val) {
        return val.toLowerCase();
      });
    } else {
      include = include.toLowerCase();
    }

    var realmDelimiter;
    // Check if realm is required
    var realmRequired = !!(self.settings.realmRequired ||
      self.settings.realmDelimiter);
    if (realmRequired) {
      realmDelimiter = self.settings.realmDelimiter;
    }
    var query = self.normalizeCredentials(credentials, realmRequired,
      realmDelimiter);

    if (realmRequired && !query.realm) {
      var err1 = new Error(g.f('{{realm}} is required'));
      err1.statusCode = 400;
      err1.code = 'REALM_REQUIRED';
      fn(err1);
      return fn.promise;
    }
    if (!query.email && !query.username) {
      var err2 = new Error(g.f('{{username}} or {{email}} is required'));
      err2.statusCode = 400;
      err2.code = 'USERNAME_EMAIL_REQUIRED';
      fn(err2);
      return fn.promise;
    }

    self.findOne({where: query}, function(err, customer) {
      var defaultError = new Error(g.f('login failed'));
      defaultError.statusCode = 401;
      defaultError.code = 'LOGIN_FAILED';

      function tokenHandler(err, token) {
        if (err) return fn(err);
        if (Array.isArray(include) ? include.indexOf('customer') !== -1 : include === 'customer') {
          token.__data.customer = customer;
        }
        fn(err, token);
      }

      if (err) {
        debug('An error is reported from Customer.findOne: %j', err);
        fn(defaultError);
      } else if (customer) {
        customer.hasPassword(credentials.password, function(err, isMatch) {
          if (err) {
            debug('An error is reported from Customer.hasPassword: %j', err);
            fn(defaultError);
          } else if (isMatch) {
            if (self.settings.emailVerificationRequired && !customer.emailVerified) {
              // Fail to log in if email verification is not done yet
              debug('User email has not been verified');
              err = new Error(g.f('login failed as the email has not been verified'));
              err.statusCode = 401;
              err.code = 'LOGIN_FAILED_EMAIL_NOT_VERIFIED';
              err.details = {
                customerId: customer.id,
              };
              fn(err);
            } else {
              if (customer.createAccessToken.length === 2) {
                customer.createAccessToken(credentials.ttl, tokenHandler);
              } else {
                customer.createAccessToken(credentials.ttl, credentials, tokenHandler);
              }
            }
          } else {
            debug('The password is invalid for user %s', query.email || query.username);
            fn(defaultError);
          }
        });
      } else {
        debug('No matching record is found for user %s', query.email || query.username);
        fn(defaultError);
      }
    });
    return fn.promise;
  };

  Customer.logout = function(tokenId, fn) {
    fn = fn || utils.createPromiseCallback();

    var err;
    if (!tokenId) {
      err = new Error(g.f('{{accessToken}} is required to logout'));
      err.status = 401;
      process.nextTick(fn, err);
      return fn.promise;
    }

    this.relations.accessTokens.modelTo.destroyById(tokenId, function(err, info) {
      if (err) {
        fn(err);
      } else if ('count' in info && info.count === 0) {
        err = new Error(g.f('Could not find {{accessToken}}'));
        err.status = 401;
        fn(err);
      } else {
        fn();
      }
    });
    return fn.promise;
  };


  Customer.observe('before delete', function(ctx, next) {
    var AccessToken = ctx.Model.relations.accessTokens.modelTo;
    var pkName = ctx.Model.definition.idName() || 'id';
    ctx.Model.find({where: ctx.where, fields: [pkName]}, function(err, list) {
      if (err) return next(err);

      var ids = list.map(function(u) { return u[pkName]; });
      ctx.where = {};
      ctx.where[pkName] = {inq: ids};

      AccessToken.destroyAll({customerId: {inq: ids}}, next);
    });
  });

  

  Customer.prototype.hasPassword = function(plain, fn) {
    fn = fn || utils.createPromiseCallback();
    if (this.password && plain) {
      bcrypt.compare(plain, this.password, function(err, isMatch) {
        if (err) return fn(err);
        fn(null, isMatch);
      });
    } else {
      fn(null, false);
    }
    return fn.promise;
  };

  Customer.changePassword = function(customerId, oldPassword, newPassword, options, cb) {
    if (cb === undefined && typeof options === 'function') {
      cb = options;
      options = undefined;
    }
    cb = cb || utils.createPromiseCallback();

    
    this.findById(customerId, options, (err, inst) => {
      if (err) return cb(err);

      if (!inst) {
        const err = new Error(`Customer ${customerId} not found`);
        Object.assign(err, {
          code: 'USER_NOT_FOUND',
          statusCode: 401,
        });
        return cb(err);
      }

      inst.changePassword(oldPassword, newPassword, options, cb);
    });

    return cb.promise;
  };


  Customer.prototype.changePassword = function(oldPassword, newPassword, options, cb) {
    if (cb === undefined && typeof options === 'function') {
      cb = options;
      options = undefined;
    }
    cb = cb || utils.createPromiseCallback();

    this.hasPassword(oldPassword, (err, isMatch) => {
      if (err) return cb(err);
      if (!isMatch) {
        const err = new Error('Invalid current password');
        Object.assign(err, {
          code: 'INVALID_PASSWORD',
          statusCode: 400,
        });
        return cb(err);
      }

      this.setPassword(newPassword, options, cb);
    });
    return cb.promise;
  };

  Customer.setPassword = function(customerId, newPassword, options, cb) {
    assert(customerId != null && customerId !== '', 'customerId is a required argument');
    assert(!!newPassword, 'newPassword is a required argument');

    if (cb === undefined && typeof options === 'function') {
      cb = options;
      options = undefined;
    }
    cb = cb || utils.createPromiseCallback();
    this.findById(customerId, options, (err, inst) => {
      if (err) return cb(err);

      if (!inst) {
        const err = new Error(`Customer ${customerId} not found`);
        Object.assign(err, {
          code: 'USER_NOT_FOUND',
          statusCode: 401,
        });
        return cb(err);
      }

      inst.setPassword(newPassword, options, cb);
    });

    return cb.promise;
  };

  Customer.prototype.setPassword = function(newPassword, options, cb) {
    assert(!!newPassword, 'newPassword is a required argument');

    if (cb === undefined && typeof options === 'function') {
      cb = options;
      options = undefined;
    }
    cb = cb || utils.createPromiseCallback();

    try {
      this.constructor.validatePassword(newPassword);
    } catch (err) {
      cb(err);
      return cb.promise;
    }

    // We need to modify options passed to patchAttributes, but we don't want
    // to modify the original options object passed to us by setPassword caller
    options = Object.assign({}, options);

    // patchAttributes() does not allow callers to modify the password property
    // unless "options.setPassword" is set.
    options.setPassword = true;

    const delta = {password: newPassword};
    this.patchAttributes(delta, options, (err, updated) => cb(err));

    return cb.promise;
  };

 

  Customer.getVerifyOptions = function() {
    const verifyOptions = {
      type: 'email',
      from: 'noreply@example.com',
    };
    return this.settings.verifyOptions || verifyOptions;
  };

  

  Customer.prototype.verify = function(verifyOptions, options, cb) {
    if (cb === undefined && typeof options === 'function') {
      cb = options;
      options = undefined;
    }
    cb = cb || utils.createPromiseCallback();

    var customer = this;
    var customerModel = this.constructor;
    var registry = customerModel.registry;

    // final assertion is performed once all options are assigned
    assert(typeof verifyOptions === 'object',
      'verifyOptions object param required when calling customer.verify()');

    // Set a default template generation function if none provided
    verifyOptions.templateFn = verifyOptions.templateFn || createVerificationEmailBody;

    // Set a default token generation function if none provided
    verifyOptions.generateVerificationToken = verifyOptions.generateVerificationToken ||
      Customer.generateVerificationToken;

    // Set a default mailer function if none provided
    verifyOptions.mailer = verifyOptions.mailer || customerModel.email ||
      registry.getModelByType(loopback.Email);

    var pkName = customerModel.definition.idName() || 'id';
    verifyOptions.redirect = verifyOptions.redirect || '/';
    var defaultTemplate = path.join(__dirname, '..', '..', 'templates', 'verify.ejs');
    verifyOptions.template = path.resolve(verifyOptions.template || defaultTemplate);
    verifyOptions.customer = customer;
    verifyOptions.protocol = verifyOptions.protocol || 'http';

    var app = customerModel.app;
    verifyOptions.host = verifyOptions.host || (app && app.get('host')) || 'localhost';
    verifyOptions.port = verifyOptions.port || (app && app.get('port')) || 3000;
    verifyOptions.restApiRoot = verifyOptions.restApiRoot || (app && app.get('restApiRoot')) || '/api';

    var displayPort = (
      (verifyOptions.protocol === 'http' && verifyOptions.port == '80') ||
      (verifyOptions.protocol === 'https' && verifyOptions.port == '443')
    ) ? '' : ':' + verifyOptions.port;

    var urlPath = joinUrlPath(
      verifyOptions.restApiRoot,
      customerModel.http.path,
      customerModel.sharedClass.findMethodByName('confirm').http.path
    );

    verifyOptions.verifyHref = verifyOptions.verifyHref ||
      verifyOptions.protocol +
      '://' +
      verifyOptions.host +
      displayPort +
      urlPath +
      '?' + qs.stringify({
        uid: '' + verifyOptions.customer[pkName],
        redirect: verifyOptions.redirect,
      });

    verifyOptions.to = verifyOptions.to || customer.email;
    verifyOptions.subject = verifyOptions.subject || g.f('Thanks for Registering');
    verifyOptions.headers = verifyOptions.headers || {};

    // assert the verifyOptions params that might have been badly defined
    assertVerifyOptions(verifyOptions);

    // argument "options" is passed depending on verifyOptions.generateVerificationToken function requirements
    var tokenGenerator = verifyOptions.generateVerificationToken;
    if (tokenGenerator.length == 3) {
      tokenGenerator(customer, options, addTokenToCustomerAndSave);
    } else {
      tokenGenerator(customer, addTokenToCustomerAndSave);
    }

    function addTokenToCustomerAndSave(err, token) {
      if (err) return cb(err);
      customer.verificationToken = token;
      customer.save(options, function(err) {
        if (err) return cb(err);
        sendEmail(customer);
      });
    }

    // TODO - support more verification types
    function sendEmail(customer) {
      verifyOptions.verifyHref += '&token=' + customer.verificationToken;
      verifyOptions.verificationToken = customer.verificationToken;
      verifyOptions.text = verifyOptions.text || g.f('Please verify your email by opening ' +
        'this link in a web browser:\n\t%s', verifyOptions.verifyHref);
      verifyOptions.text = verifyOptions.text.replace(/\{href\}/g, verifyOptions.verifyHref);

      // argument "options" is passed depending on templateFn function requirements
      var templateFn = verifyOptions.templateFn;
      if (templateFn.length == 3) {
        templateFn(verifyOptions, options, setHtmlContentAndSend);
      } else {
        templateFn(verifyOptions, setHtmlContentAndSend);
      }

      function setHtmlContentAndSend(err, html) {
        if (err) return cb(err);

        verifyOptions.html = html;

        // Remove verifyOptions.template to prevent rejection by certain
        // nodemailer transport plugins.
        delete verifyOptions.template;

        // argument "options" is passed depending on Email.send function requirements
        var Email = verifyOptions.mailer;
        if (Email.send.length == 3) {
          Email.send(verifyOptions, options, handleAfterSend);
        } else {
          Email.send(verifyOptions, handleAfterSend);
        }

        function handleAfterSend(err, email) {
          if (err) return cb(err);
          cb(null, {email: email, token: customer.verificationToken, uid: customer[pkName]});
        }
      }
    }

    return cb.promise;
  };

  function assertVerifyOptions(verifyOptions) {
    assert(verifyOptions.type, 'You must supply a verification type (verifyOptions.type)');
    assert(verifyOptions.type === 'email', 'Unsupported verification type');
    assert(verifyOptions.to, 'Must include verifyOptions.to when calling customer.verify() ' +
      'or the customer must have an email property');
    assert(verifyOptions.from, 'Must include verifyOptions.from when calling customer.verify()');
    assert(typeof verifyOptions.templateFn === 'function',
      'templateFn must be a function');
    assert(typeof verifyOptions.generateVerificationToken === 'function',
      'generateVerificationToken must be a function');
    assert(verifyOptions.mailer, 'A mailer function must be provided');
    assert(typeof verifyOptions.mailer.send === 'function', 'mailer.send must be a function ');
  }

  function createVerificationEmailBody(verifyOptions, options, cb) {
    var template = loopback.template(verifyOptions.template);
    var body = template(verifyOptions);
    cb(null, body);
  }

  Customer.generateVerificationToken = function(customer, options, cb) {
    crypto.randomBytes(64, function(err, buf) {
      cb(err, buf && buf.toString('hex'));
    });
  };

 
  Customer.confirm = function(uid, token, redirect, fn) {
    fn = fn || utils.createPromiseCallback();
    this.findById(uid, function(err, customer) {
      if (err) {
        fn(err);
      } else {
        if (customer && customer.verificationToken === token) {
          customer.verificationToken = null;
          customer.emailVerified = true;
          customer.save(function(err) {
            if (err) {
              fn(err);
            } else {
              fn();
            }
          });
        } else {
          if (customer) {
            err = new Error(g.f('Invalid token: %s', token));
            err.statusCode = 400;
            err.code = 'INVALID_TOKEN';
          } else {
            err = new Error(g.f('User not found: %s', uid));
            err.statusCode = 404;
            err.code = 'USER_NOT_FOUND';
          }
          fn(err);
        }
      }
    });
    return fn.promise;
  };

  

  Customer.resetPassword = function(options, cb) {
    cb = cb || utils.createPromiseCallback();
    var CustomerModel = this;
    var ttl = CustomerModel.settings.resetPasswordTokenTTL || DEFAULT_RESET_PW_TTL;
    options = options || {};
    if (typeof options.email !== 'string') {
      var err = new Error(g.f('Email is required'));
      err.statusCode = 400;
      err.code = 'EMAIL_REQUIRED';
      cb(err);
      return cb.promise;
    }

    try {
      if (options.password) {
        CustomerModel.validatePassword(options.password);
      }
    } catch (err) {
      return cb(err);
    }
    var where = {
      email: options.email,
    };
    if (options.realm) {
      where.realm = options.realm;
    }
    CustomerModel.findOne({where: where}, function(err, customer) {
      if (err) {
        return cb(err);
      }
      if (!customer) {
        err = new Error(g.f('Email not found'));
        err.statusCode = 404;
        err.code = 'EMAIL_NOT_FOUND';
        return cb(err);
      }
      // create a short lived access token for temp login to change password
      // TODO(ritch) - eventually this should only allow password change
      if (CustomerModel.settings.emailVerificationRequired && !customer.emailVerified) {
        err = new Error(g.f('Email has not been verified'));
        err.statusCode = 401;
        err.code = 'RESET_FAILED_EMAIL_NOT_VERIFIED';
        return cb(err);
      }

      if (CustomerModel.settings.restrictResetPasswordTokenScope) {
        const tokenData = {
          ttl: ttl,
          scopes: ['reset-password'],
        };
        customer.createAccessToken(tokenData, options, onTokenCreated);
      } else {
        customer.createAccessToken(ttl, onTokenCreated);
      }

      function onTokenCreated(err, accessToken) {
        if (err) {
          return cb(err);
        }
        cb();
        CustomerModel.emit('resetPasswordRequest', {
          email: options.email,
          accessToken: accessToken,
          customer: customer,
          options: options,
        });
      }
    });

    return cb.promise;
  };

  Customer.hashPassword = function(plain) {
    this.validatePassword(plain);
    var salt = bcrypt.genSaltSync(this.settings.saltWorkFactor || SALT_WORK_FACTOR);
    return bcrypt.hashSync(plain, salt);
  };

  Customer.validatePassword = function(plain) {
    var err;
    if (!plain || typeof plain !== 'string') {
      err = new Error(g.f('Invalid password.'));
      err.code = 'INVALID_PASSWORD';
      err.statusCode = 422;
      throw err;
    }

    // Bcrypt only supports up to 72 bytes; the rest is silently dropped.
    var len = Buffer.byteLength(plain, 'utf8');
    if (len > MAX_PASSWORD_LENGTH) {
      err = new Error(g.f('The password entered was too long. Max length is %d (entered %d)',
        MAX_PASSWORD_LENGTH, len));
      err.code = 'PASSWORD_TOO_LONG';
      err.statusCode = 422;
      throw err;
    }
  };

  Customer._invalidateAccessTokensOfCustomers = function(customerIds, options, cb) {
    if (typeof options === 'function' && cb === undefined) {
      cb = options;
      options = {};
    }

    if (!Array.isArray(customerIds) || !customerIds.length)
      return process.nextTick(cb);

    var accessTokenRelation = this.relations.accessTokens;
    if (!accessTokenRelation)
      return process.nextTick(cb);

    var AccessToken = accessTokenRelation.modelTo;
    var query = {customerId: {inq: customerIds}};
    var tokenPK = AccessToken.definition.idName() || 'id';
    if (options.accessToken && tokenPK in options.accessToken) {
      query[tokenPK] = {neq: options.accessToken[tokenPK]};
    }
    var relatedCustomer = AccessToken.relations.customer;
    var isRelationPolymorphic = relatedCustomer && relatedCustomer.polymorphic &&
      !relatedCustomer.modelTo;
    if (isRelationPolymorphic) {
      query.principalType = this.modelName;
    }
    AccessToken.deleteAll(query, options, cb);
  };


  Customer.setup = function() {
    // We need to call the base class's setup method
    Customer.base.setup.call(this);
    var CustomerModel = this;

    // max ttl
    this.settings.maxTTL = this.settings.maxTTL || DEFAULT_MAX_TTL;
    this.settings.ttl = this.settings.ttl || DEFAULT_TTL;

    CustomerModel.setter.email = function(value) {
      if (!CustomerModel.settings.caseSensitiveEmail) {
        this.$email = value.toLowerCase();
      } else {
        this.$email = value;
      }
    };

    CustomerModel.setter.password = function(plain) {
      if (typeof plain !== 'string') {
        return;
      }
      if (plain.indexOf('$2a$') === 0 && plain.length === 60) {
        // The password is already hashed. It can be the case
        // when the instance is loaded from DB
        this.$password = plain;
      } else {
        this.$password = this.constructor.hashPassword(plain);
      }
    };

    // Make sure emailVerified is not set by creation
    CustomerModel.beforeRemote('create', function(ctx, customer, next) {
      var body = ctx.req.body;
      if (body && body.emailVerified) {
        body.emailVerified = false;
      }
      next();
    });

    CustomerModel.remoteMethod(
      'login',
      {
        description: 'Login a customer with username/email and password.',
        accepts: [
          {arg: 'credentials', type: 'object', required: true, http: {source: 'body'}},
          {arg: 'include', type: ['string'], http: {source: 'query'},
            description: 'Related objects to include in the response. ' +
            'See the description of return value for more details.'},
        ],
        returns: {
          arg: 'accessToken', type: 'object', root: true,
          description:
            g.f('The response body contains properties of the {{AccessToken}} created on login.\n' +
            'Depending on the value of `include` parameter, the body may contain ' +
            'additional properties:\n\n' +
            '  - `customer` - `U+007BCustomerU+007D` - Data of the currently logged in customer. ' +
            '{{(`include=customer`)}}\n\n'),
        },
        http: {verb: 'post'},
      }
    );

    CustomerModel.remoteMethod(
      'logout',
      {
        description: 'Logout a customer with access token.',
        accepts: [
          {arg: 'access_token', type: 'string', http: function(ctx) {
            var req = ctx && ctx.req;
            var accessToken = req && req.accessToken;
            var tokenID = accessToken ? accessToken.id : undefined;

            return tokenID;
          }, description: 'Do not supply this argument, it is automatically extracted ' +
            'from request headers.',
          },
        ],
        http: {verb: 'all'},
      }
    );

    CustomerModel.remoteMethod(
      'prototype.verify',
      {
        description: 'Trigger customer\'s identity verification with configured verifyOptions',
        accepts: [
          {arg: 'verifyOptions', type: 'object', http: ctx => this.getVerifyOptions()},
          {arg: 'options', type: 'object', http: 'optionsFromRequest'},
        ],
        http: {verb: 'post'},
      }
    );

    CustomerModel.remoteMethod(
      'confirm',
      {
        description: 'Confirm a customer registration with identity verification token.',
        accepts: [
          {arg: 'uid', type: 'string', required: true},
          {arg: 'token', type: 'string', required: true},
          {arg: 'redirect', type: 'string'},
        ],
        http: {verb: 'get', path: '/confirm'},
      }
    );

    CustomerModel.remoteMethod(
      'resetPassword',
      {
        description: 'Reset password for a customer with email.',
        accepts: [
          {arg: 'options', type: 'object', required: true, http: {source: 'body'}},
        ],
        http: {verb: 'post', path: '/reset'},
      }
    );

    CustomerModel.remoteMethod(
      'changePassword',
      {
        description: 'Change a customer\'s password.',
        accepts: [
          {arg: 'id', type: 'any',
            http: ctx => ctx.req.accessToken && ctx.req.accessToken.customerId,
          },
          {arg: 'oldPassword', type: 'string', required: true, http: {source: 'form'}},
          {arg: 'newPassword', type: 'string', required: true, http: {source: 'form'}},
          {arg: 'options', type: 'object', http: 'optionsFromRequest'},
        ],
        http: {verb: 'POST', path: '/change-password'},
      }
    );

    const setPasswordScopes = CustomerModel.settings.restrictResetPasswordTokenScope ?
      ['reset-password'] : undefined;

    CustomerModel.remoteMethod(
      'setPassword',
      {
        description: 'Reset customer\'s password via a password-reset token.',
        accepts: [
          {arg: 'id', type: 'any',
            http: ctx => ctx.req.accessToken && ctx.req.accessToken.customerId,
          },
          {arg: 'newPassword', type: 'string', required: true, http: {source: 'form'}},
          {arg: 'options', type: 'object', http: 'optionsFromRequest'},
        ],
        accessScopes: setPasswordScopes,
        http: {verb: 'POST', path: '/reset-password'},
      }
    );

    CustomerModel.afterRemote('confirm', function(ctx, inst, next) {
      if (ctx.args.redirect !== undefined) {
        if (!ctx.res) {
          return next(new Error(g.f('The transport does not support HTTP redirects.')));
        }
        ctx.res.location(ctx.args.redirect);
        ctx.res.status(302);
      }
      next();
    });

    // default models
    assert(loopback.Email, 'Email model must be defined before Customer model');
    CustomerModel.email = loopback.Email;

    assert(loopback.AccessToken, 'AccessToken model must be defined before Customer model');
    CiustomerModel.accessToken = loopback.AccessToken;

    CustomerModel.validate('email', emailValidator, {
      message: g.f('Must provide a valid email'),
    });

    // Realm users validation
    if (CustomerModel.settings.realmRequired && CustomerModel.settings.realmDelimiter) {
      CustomerModel.validatesUniquenessOf('email', {
        message: 'Email already exists',
        scopedTo: ['realm'],
      });
      CustomerModel.validatesUniquenessOf('username', {
        message: 'Customer already exists',
        scopedTo: ['realm'],
      });
    } else {
      CustomerModel.validatesUniquenessOf('email', {message: 'Email already exists'});
      CustomerModel.validatesUniquenessOf('username', {message: 'Customer already exists'});
    }

    return CustomerModel;
  };


  Customer.setup();
  Customer.observe('access', function normalizeEmailCase(ctx, next) {
    if (!ctx.Model.settings.caseSensitiveEmail && ctx.query.where &&
        ctx.query.where.email && typeof(ctx.query.where.email) === 'string') {
      ctx.query.where.email = ctx.query.where.email.toLowerCase();
    }
    next();
  });

  Customer.observe('before save', function rejectInsecurePasswordChange(ctx, next) {
    const CustomerModel = ctx.Model;
    if (!CustomerModel.settings.rejectPasswordChangesViaPatchOrReplace) {
      // In legacy password flow, any DAO method can change the password
      return next();
    }

    if (ctx.isNewInstance) {
      return next();
    }
    const data = ctx.data || ctx.instance;
    const isPasswordChange = 'password' in data;
    if (ctx.options.setPassword) {
      // Verify that only the password is changed and nothing more or less.
      if (Object.keys(data).length > 1 || !isPasswordChange) {
        // This is a programmer's error, use the default status code 500
        return next(new Error(
          'Invalid use of "options.setPassword". Only "password" can be ' +
          'changed when using this option.'));
      }

      return next();
    }

    if (!isPasswordChange) {
      return next();
    }

    const err = new Error(
      'Changing user password via patch/replace API is not allowed. ' +
      'Use changePassword() or setPassword() instead.');
    err.statusCode = 401;
    err.code = 'PASSWORD_CHANGE_NOT_ALLOWED';
    next(err);
  });

  Customer.observe('before save', function prepareForTokenInvalidation(ctx, next) {
    if (ctx.isNewInstance) return next();
    if (!ctx.where && !ctx.instance) return next();

    var pkName = ctx.Model.definition.idName() || 'id';
    var where = ctx.where;
    if (!where) {
      where = {};
      where[pkName] = ctx.instance[pkName];
    }

    ctx.Model.find({where: where}, ctx.options, function(err, customerInstances) {
      if (err) return next(err);
      ctx.hookState.originalCustomerData = customerInstances.map(function(u) {
        var customeromer = {};
        customer[pkName] = u[pkName];
        customer.email = u.email;
        customer.password = u.password;
        return customer;
      });
      var emailChanged;
      if (ctx.instance) {
        emailChanged = ctx.instance.email !== ctx.hookState.originalCustomerData[0].email;
        if (emailChanged && ctx.Model.settings.emailVerificationRequired) {
          ctx.instance.emailVerified = false;
        }
      } else if (ctx.data.email) {
        emailChanged = ctx.hookState.originalCustomerData.some(function(data) {
          return data.email != ctx.data.email;
        });
        if (emailChanged && ctx.Model.settings.emailVerificationRequired) {
          ctx.data.emailVerified = false;
        }
      }

      next();
    });
  });

  Customer.observe('after save', function invalidateOtherTokens(ctx, next) {
    if (!ctx.instance && !ctx.data) return next();
    if (!ctx.hookState.originalCustomerData) return next();

    var pkName = ctx.Model.definition.idName() || 'id';
    var newEmail = (ctx.instance || ctx.data).email;
    var newPassword = (ctx.instance || ctx.data).password;

    if (!newEmail && !newPassword) return next();

    var customerIdsToExpire = ctx.hookState.originalCustomerData.filter(function(u) {
      return (newEmail && u.email !== newEmail) ||
        (newPassword && u.password !== newPassword);
    }).map(function(u) {
      return u[pkName];
    });
    ctx.Model._invalidateAccessTokensOfCustomers(customerIdsToExpire, ctx.options, next);
  });
};

function emailValidator(err, done) {
  var value = this.email;
  if (value == null)
    return;
  if (typeof value !== 'string')
    return err('string');
  if (value === '') return;
  if (!isEmail.validate(value))
    return err('email');
}

function joinUrlPath(args) {
  var result = arguments[0];
  for (var ix = 1; ix < arguments.length; ix++) {
    var next = arguments[ix];
    result += result[result.length - 1] === '/' && next[0] === '/' ?
      next.slice(1) : next;
  }
  return result;
}