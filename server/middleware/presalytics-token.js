// if request is has bearer etoken, authenticate with presalytics 
// redirect user to signin
async function mustBeAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    return res.utils.unauthorized();
  }
  
  module.exports = mustBeAuthenticated;
  