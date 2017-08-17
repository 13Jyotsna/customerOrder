'use strict';
var config = require('../../server/server.js');
var path = require('path');
// var async = require('async');
// var md5 = require('md5');
var loopback = require('loopback');
// var emailFrom = {
//   email: "reachus@olivetheory.com",
//   name: "Olive Theory"
// }
// var HOST = "social.olivetheory.com";

  module.exports = function(Customer) {
  	Customer.validatesUniquenessOf('email', {message: 'email is not unique'});
  // 	customer.observe("before save", function(ctx, next) {
  //   if (ctx.isNewInstance) {
  //     if (ctx.instance) {
  //       ctx.instance.created = new Date();
  //     }
  //   } else {
  //     if (ctx.instance) {
  //       ctx.instance.updated = new Date();
  //     }
  //   }
  //   return next();
  // });

  	

  	//var Customer = app.models.Customer;
  	 Customer.signup = function(data){

  	 	
  	 

  	 	//console.log(data)
  	 

  	 	//return cb(data)
  	 }

  Customer.remoteMethod(
    'signup', {
      accepts: {
        arg: 'data',
        type: 'object',
        http: {
          source: 'body'
        },
        required: true
      },
      http: {
        verb: "post",
        path: "/signup"
      },
      returns: {
        type: 'object',
        root: true
      }
    }
  );

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
      var err1 = new Error('{{realm}} is required');
      err1.statusCode = 400;
      err1.code = 'REALM_REQUIRED';
      fn(err1);
      return fn.promise;
    }
    if (!query.email && !query.username) {
      var err2 = new Error('{{username}} or {{email}} is required');
      err2.statusCode = 400;
      err2.code = 'USERNAME_EMAIL_REQUIRED';
      fn(err2);
      return fn.promise;
    }

    self.findOne({where: query}, function(err, customer) {
      var defaultError = new Error('login failed');
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
              err = new Error(f('login failed as the email has not been verified'));
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

  Customer.normalizeCredentials = function(credentials, realmRequired, realmDelimiter) {
    var query = {};
    credentials = credentials || {};
    if (!realmRequired) {
      if (credentials.email) {
        query.email = credentials.email;
      } else if (credentials.username) {
        query.username = credentials.username;
      } else if (credentials.phone) {
        query.phone = credentials.phone;
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


  Customer.logout = function(tokenId, fn) {
    fn = fn || utils.createPromiseCallback();

    var err;
    if (!tokenId) {
      err = new Error('{{accessToken}} is required to logout');
      err.status = 401;
      process.nextTick(fn, err);
      return fn.promise;
    }

    this.relations.accessTokens.modelTo.destroyById(tokenId, function(err, info) {
      if (err) {
        fn(err);
      } else if ('count' in info && info.count === 0) {
        err = new Error('Could not find {{accessToken}}');
        err.status = 401;
        fn(err);
      } else {
        fn();
      }
    });
    return fn.promise;
  };

  //Customer.login = function(data,callback){

  	//console.log(data);

		
  //}

  Customer.remoteMethod(
    'login', {
      accepts: {
        arg: 'data',
        type: 'object',
        http: {
          source: 'body'
        },
        required: true
      },
      http: {
        verb: "post",
        path: "/login"
      },
      returns: {
        type: 'object',
        root: true
      }
    }
  );


  Customer.beforeRemote("logout", function(ctx, modelInstance, next) {
    try {
      if (ctx.req) {
        ctx.req.logout();
      }
    } catch (err) {
      return next(err);
    }
    next();
  });

//   app.get('/logout', function(req, res, next) {
//   if (!req.accessToken) return res.sendStatus(401); //return 401:unauthorized if accessToken is not present
//   User.logout(req.accessToken.id, function(err) {
//     if (err) return next(err);
//     res.redirect('/'); //on successful logout, redirect
//   });
// });

  
  Customer.social = function(data, next) {
    
  }

  Customer.remoteMethod(
    'social', {
      accepts: {
        arg: 'data',
        type: 'object',
        http: {
          source: 'body'
        }
      },
      http: {
        verb: "post",
        path: "/social"
      },
      returns: {
        type: 'object',
        root: true
      }
    }
  );

  Customer.reverify = function(data, cb) {

  	if (!data) {
      var e = new Error();
      e.status = 422;
      e.code = "UNPROCESSABLE_ENTITY";
      e.message = "Data instance is not defined";
      return cb(e);
    }
    if (!data.email) {
      var e = new Error();
      e.status = 422;
      e.code = "UNPROCESSABLE_ENTITY";
      e.message = "Email is undefined";
      return cb(e);
    }
    Customer.findOne({
      where: {
        email: data.email
      }
    }, function(err, customer) {
      if (err) {
        return cb(err);
      }
      if (!customer) {
        var e = new Error();
        e.status = 404;
        e.code = "MODEL_NOT_FOUND";
        e.message = "Email not registered";
        return cb(e);
      }
      if (customer.emailVerified) {
        var e = new Error();
        e.status = 400;
        e.code = "BAD_REQUEST";
        e.message = "Email is already verified";
        return cb(e);
      }
      sendVerifyMail(customer, cb);
    });
  }

  Customer.remoteMethod(
    'reverify', {
      accepts: {
        arg: 'data',
        type: 'object',
        http: {
          source: 'body'
        }
      },
      http: {
        verb: "post",
        path: "/reverify"
      },
      returns: {
        type: 'object',
        root: true
      }
    }
  );

  Customer.setPassword = function(doc, cb) {
   
  }

  Customer.remoteMethod(
    'setPassword', {
      accepts: {
        arg: "password",
        type: "object",
        http: {
          source: "body"
        }
      },
      http: {
        verb: "post",
        path: "/set-password"
      },
      returns: {
        type: 'object',
        root: true
      }
    }
  );


  
  Customer.findByName = function(customerName, callback) {
    Customer.findOne({
      where: {
        customerName: customerName
      }
    }, function(err, customer) {
      if (err) {
        console.log(err);
        return callback(err);
      }
      callback(null, customer);
    });
  }

  Customer.remoteMethod(
    'findByName', {
      accepts: [{
        arg: 'customerName',
        type: 'string',
        required: true
      }],
      http: {
        verb: "get",
        path: "/byname"
      },
      returns: {
        type: 'object',
        root: true
      }
    }
  );
};
