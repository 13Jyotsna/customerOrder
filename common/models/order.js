'use strict';

module.exports = function(Order) {
	// Order.observe("before save", function(ctx, next) {
 //    if (ctx.isNewInstance) {
 //      if (ctx.instance) {
 //        ctx.instance.created = new Date();
 //      }
 //    } else {
 //      if (ctx.instance) {
 //        ctx.instance.updated = new Date();
 //      }
 //    }
 //    return next();
 //  });

	Order.status = function(cb) {
    var currentDate = new Date();
    var currentHour = currentDate.getHours();
    var OPEN_HOUR = 6;
    var CLOSE_HOUR = 20;
    console.log('Current hour is %d', currentHour);
    var response;
    if (currentHour > OPEN_HOUR && currentHour < CLOSE_HOUR) {
      response = 'Your order will be delivered soon';
    } else {
      response = 'Sorry for the delay.';
    }
    cb(null, response);
  };
  Order.remoteMethod(
    'status', {
      http: {
        path: '/status',
        verb: 'get',
      },
      returns: {
        arg: 'status',
        type: 'string',
      },
    }
  );

 // Order.verifyOrder = function(orderId, callback) {

 //    if (!orderId) {
 //     return callback(new Error("OrderId is required."));
 //   }
    
 //    Order.findOne({
 //      where: {
 //       orderId: orderId,
 //        verified: true
 //     }
 //   }, function(err, orderInstance) {
 //      if (err) {
 //       console.log(err);
 //       return callback(err);
 //      }
 //      if (!orderInstance) {
 //        return callback(null, {
 //          verified: false
 //        });
 //      }
 //      if (orderInstance.verfied) {
 //        return callback(null, {
 //          verified: orderInstance.verified
 //        })
 //      } else {
 //        orderInstance.verified = true;
 //        orderInstance.save(function(err) {
 //          if (err) {
 //            return callback(err);
 //          }
 //          return callback(null, {
 //            verified: true
 //          });
 //        });
 //      }
 //    });
 //  }

 //  Order.remoteMethod(
 //    'verifyOrder', {
 //      accepts: [{
 //        arg: 'orderId',
 //        type: 'string',
 //        required: true
       
 //      }],
 //      http: {
 //        verb: "get"
 //      },
 //      returns: {
 //        type: 'object',
 //        root: true
 //      }
 //    }
 //  );
};
