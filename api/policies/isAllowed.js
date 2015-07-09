/**
 * isAllowed
 * @description :: Policy to check if this request goes from our applications
 */

module.exports = function (req, res, next) {
  var token = req.headers['application-token'];

  if (token && token === "f57952934e414bea35fc3ea22249800108b33124bc4804693e34e655f2fd3d8a") {
    next();
  } else {
    res.unauthorized(null, null, 'You must provide application token');
  }
};
