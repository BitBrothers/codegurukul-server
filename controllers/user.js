var jwt = require('jwt-simple');
var moment = require('moment');
var crypto = require('crypto');
var path = require('path');
var course = require('../controllers/course');
var email = require('../controllers/email');
var secrets = require('../config/secrets');
var config = secrets();
var msg = require('../messages');
var validator = require('email-validator');
var request = require('request');
/**
 * Model.
 */
var User = require('../models/User');

var tokenSecret = config.sessionSecret;

function createJWT(user) {
  var payload = {
    sub: user._id,
    iat: moment().unix(),
    exp: moment().add(14, 'days').unix()
  };
  return jwt.encode(payload, tokenSecret);
}


exports.isLoginOptional = function(req, res, next) {
  if (req.headers.authorization) {
    var token = req.headers.authorization;
    //.split(' ')[1];
    try {
      var decoded = jwt.decode(token, tokenSecret);
      if (decoded.exp >= Date.now()) {
        console.log("token exp");
        res.status(403).send(msg.et);
      } else {
        req.user = decoded.user;
        return next();
      }
    } catch (err) {
      req.user = false;
      return next();
    }
  } else {
    req.user = false;
    return next();

  }
};

exports.isLogin = function(req, res, next) {
  if (req.headers.authorization) {
    var token = req.headers.authorization;
    //.split(' ')[1];
    try {
      var decoded = jwt.decode(token, tokenSecret);
      if (decoded.exp <= Date.now()) {
        res.status(407).send(msg.et);
      } else {
        req.user = decoded.user;
        return next();
      }
    } catch (err) {
      return res.status(500).send(msg.at);
    }
  } else {
    if (req.flag) {
      // next();
    } else {
      res.status(401).send(msg.unauth);
    }

  }
};

exports.ensureAuthenticated = function(req, res, next) {
  if (!req.headers.authorization) {
    return res.status(401).send({ message: 'Please make sure your request has an Authorization header' });
  }
  var token = req.headers.authorization.split(' ')[1];

  var payload = null;
  try {
    payload = jwt.decode(token, config.TOKEN_SECRET);
  }
  catch (err) {
    return res.status(401).send({ message: err.message });
  }

  if (payload.exp <= moment().unix()) {
    return res.status(401).send({ message: 'Token has expired' });
  }
  req.user = payload.sub;
  next();
};

exports.putUserProfile = function(req, res) {
  User.findById(req.user, function(err, user) {
    if (!user) {
      return res.status(400).send({ message: 'User not found' });
    }
    user.displayName = req.body.displayName || user.displayName;
    user.email = req.body.email || user.email;
    user.save(function(err) {
      res.status(200).end();
    });
  });
};

exports.isAdmin = function(req, res, next) {
  if (req.headers.authorization) {
    var token = req.headers.authorization;
    //.split(' ')[1];
    try {
      var decoded = jwt.decode(token, tokenSecret);
      if (decoded.user.role == 'admin') {
        if (decoded.exp <= Date.now()) {
          res.status(404).send(msg.et);
        } else {
          req.user = decoded.user;
          return next();
        }
      } else {
        return res.status(404).send(msg.unauth);
      }
    } catch (err) {
      return res.status(404).send(msg.at);
    }
  } else {
    res.status(404).send(msg.unauth);
  }
};

exports.signup = function(req, res, next) {
  if (req.existingUser) {
    return next();
  }
  if (!validator.validate(req.body.email))
    return res.status(400).send(msg.inem);
  var user = new User({
    email: req.body.email,
    password: req.body.password,
    username: req.body.username,
    mobile: req.body.mobile,
    profile: {
      fullname: req.body.fullname,
      type: req.body.type,
      college: req.body.college,
      year: req.body.year,
      stream: req.body.stream,
      organization: req.body.organization,
      workDesc: req.body.workDesc
    }
  });
  if (req.body.referalCode) {
    user.extReferalCode = req.body.referalCode;
  };
  user.save(function(err, user, numberAffected) {
    if (err) res.status(400).send(err);
    else {
      if(!req.admin) res.status(200).send(msg.signup);
      email.sendSignupEmail(user.email, user.username, user.verificationCode); 
      if (req.body.lead) 
        if (req.body.lead.cslug && req.body.lead.sid) course.addLead(user.id, req.body.lead.cslug, req.body.lead.sid);
      if (req.admin) {
        email.sendPassword(user.email, user.username, req.body.password);     
        req.user = user;
        next();
      }
    }

  });
};

exports.signupResend = function (req, res) {
  if (!validator.validate(req.body.email))
    return res.status(400).send(msg.inem);
  User.findOne({
    email: req.body.email
  }, function(err, user) {
    if (!user) return res.status(401).send(msg.unf);
    if (user.verified) return res.status(200).send(msg.alver);
    email.sendSignupEmail(user.email, user.username, user.verificationCode); 
    res.status(200).send(msg.verifySent);
  });
};

exports.signupVerify = function (req, res) {
  if (!req.body.verificationCode)
    return res.status(400).send(msg.inco);
  User.findOne({
    verificationCode: req.body.verificationCode
  }, function(err, user) {
    if (!user) return res.status(401).send(msg.inco);
    if (user.verified) return res.status(200).send(msg.alver);
    user.verified = true;
    User.findOne({
      referalCode: user.extReferalCode
    }, function(err, refUser) {
      if (!refUser) {
        user.points = 0;
      } else{
        refUser.points = refUser.points + 100;
        user.points = 100;
        refUser.save(function(err, refUser, numberAffected) {
          if(err) console.log(err);
        })
      };
      user.save(function(err, user, numberAffected) {
        if (err) res.status(400).send(err);
        else {
          res.status(200).send(msg.verified);
        }

      });
    })
  });
};

exports.postLogin = function(req, res) {
  User.findOne({ email: req.body.email }, '+password', function(err, user) {
    if (!user) {
      return res.status(401).send({ message: 'Wrong email and/or password' });
    }
    user.comparePassword(req.body.password, function(err, isMatch) {
      if (!isMatch) {
        return res.status(401).send({ message: 'Wrong email and/or password' });
      }
      res.send({ token: createJWT(user) });
    });
  });
};

exports.githubAuth = function(req, res) { //user model structure changed (slug, username moved out of profile)
  var profile = req.body.profile;
  User.findOne({
    email: profile.emails[0].value
  }, function(err, existingUser) {
    if (err) res.send(err);

    if (existingUser) {
      console.log('heere');
      var token = createJwtToken(existingUser);
      var tempy = {
        profile: existingUser.profile
      };
      return res.send({
        token: token,
        user: tempy
      });
    }
    var user = new User();
    user.profile.fullname = profile.fullname;
    user.email = profile.emails[0].value;
    user.save(function(err) {
      if (err) return next(err);
      else {
        var token = createJwtToken(user);
        var tempy = {
          profile: user.profile
        };
        res.send({
          token: token,
          user: tempy
        });
      }

    });
  });
};

exports.linkedinAuth = function(req, res) { //user model structure changed (slug, username moved out of profile)
  var profile = req.body.profile;
  User.findOne({
    email: profile.emails[0].value
  }, function(err, existingUser) {
    if (err) res.send(err);

    if (existingUser) {
      console.log('heere');
      var token = createJwtToken(existingUser);
      var tempy = {
        profile: existingUser.profile
      };
      return res.send({
        token: token,
        user: tempy
      });
    }
    var user = new User();
    user.profile.fullname = profile.fullname;
    user.email = profile.emails[0].value;
    user.save(function(err) {
      if (err) return next(err);
      else {
        var token = createJwtToken(user);
        var tempy = {
          profile: user.profile
        };
        res.send({
          token: token,
          user: tempy
        });
      }

    });
  });
};

exports.facebookAuth = function(req, res) { //user model structure changed (slug, username moved out of profile)
  var accessTokenUrl = 'https://graph.facebook.com/v2.3/oauth/access_token';
  var graphApiUrl = 'https://graph.facebook.com/v2.3/me';
  var params = {
    code: req.body.code,
    client_id: req.body.clientId,
    client_secret: config.facebook.clientSecret,
    redirect_uri: req.body.redirectUri
  };
  console.log(params);
  console.log(req.body);
  request.get({ url: accessTokenUrl, qs: params, json: true }, function(err, response, accessToken) {
    if (response.statusCode !== 200) {
      return res.status(500).send({ message: accessToken.error.message });
    }
    request.get({ url: graphApiUrl, qs: accessToken, json: true }, function(err, response, profile) {
      if (response.statusCode !== 200) {
        return res.status(500).send({ message: profile.error.message });
      }
      if (req.headers.authorization) {
        User.findOne({ facebook: profile.id }, function(err, existingUser) {
          if (existingUser) {
            return res.status(409).send({ message: 'There is already a Facebook account that belongs to you' });
          }
          var token = req.headers.authorization.split(' ')[1];
          var payload = jwt.decode(token, tokenSecret);
          User.findById(payload.sub, function(err, user) {
            if (!user) {
              return res.status(400).send({ message: 'User not found' });
            }
            user.facebook = profile.id;
            user.profile.picture = user.picture || 'https://graph.facebook.com/v2.3/' + profile.id + '/picture?type=large';
            user.fullname = user.fullname || profile.name;
            user.profile.email = profile.email;
            user.save(function() {
              var token = createJWT(user);
              res.send({ token: token });
            });
          });
        });
      } else {
        User.findOne({ facebook: profile.id }, function(err, existingUser) {
          if (existingUser) {
            var token = createJWT(existingUser);
            return res.send({ token: token });
          }
          var user = new User();
          user.facebook = profile.id;
          user.picture = 'https://graph.facebook.com/' + profile.id + '/picture?type=large';
          user.fullname = profile.name;
          user.profile.email = profile.email;
          user.save(function() {
            var token = createJWT(user);
            res.send({ token: token });
          });
        });
      }
    });
  });
};

exports.googleAuth = function(req, res) { //user model structure changed (slug, username moved out of profile)
  var profile = req.body.profile;
  User.findOne({
    email: profile.emails[0].value
  }, function(err, existingUser) {
    if (err) res.send(err);

    if (existingUser) {
      console.log('heere');
      var token = createJwtToken(existingUser);
      var tempy = {
        profile: existingUser.profile
      };
      return res.send({
        token: token,
        user: tempy
      });
    }
    var user = new User();
    user.profile.fullname = profile.fullname;
    user.email = profile.emails[0].value;
    user.save(function(err) {
      if (err) return next(err);
      else {
        var token = createJwtToken(user);
        var tempy = {
          profile: user.profile
        };
        res.send({
          token: token,
          user: tempy
        });
      }

    });
  });
};

exports.hasEmail = function(req, res, next) {
  console.log("hasEmail");
  if (!req.query.email) {
    return res.send(400, {
      message: 'Email parameter is required.'
    });
  }
  if (!validator.validate(req.query.email))
    return res.status(400).send(msg.inem);

  User.findOne({
    email: req.query.email
  }, function(err, user) {
    if (err) return next(err);
    console.log(user);
    res.send({
      available: !user
    });
  });
};

exports.getUserProfile = function(req, res) {
  User.findById(req.user, function(err, user) {
    res.send(user);
  });
};

exports.getUser = function(req, res) {
  if (req.user.slug == req.params.uslug) {
    User.findById(req.user._id)
      .select('_id profile courses points slug username mobile email badges referalCode')
      .populate({
        path: 'badges._id'
      })
      .populate({
        path: 'courses._id',
        select: '_id slug name'
      })
      .exec(function(err, user) {
        if (err)
          res.status(400).send(err);
        else if (!user) {
          res.status(404).send(msg.unf);
        } else {
          console.log(user);
          var temp = user;
          if (user.badges.length)
            for (var i = 0; i < user.badges.length; i++) {
              temp.badges[i] = user.badges[i]._id;
            };
          console.log(temp)
          res.json(user);
        }
      });
  } else {
    res.status(404).send(msg.unauth);
  }
};

exports.getUserLog = function(req, res) {
  User.findOne({
    'profile.slug': req.params.uslug
  }, function(err, user) {
    if (err)
      res.status(400).send(err);
    else {
      res.json(complaint.log);
    }
  });
};

exports.changeUserPassword = function(req, res, next) {
  // console.log(req.body);
  User.findById(req.user._id, function(err, user) {
    if (err)
      res.status(400).send(err);
    else if (!user) {
      res.status(404).send(msg.unf);
    } else {
      user.comparePassword(req.body.oldPassword, function(err, isMatch) {
        if (err)
          res.status(400).send(err);
        else if (!isMatch) {
          res.status(401).send(msg.iop);
        } else {
          user.password = req.body.newPassword;
          user.save(function(err, user) {
            if (err)
              res.status(400).send(err);
            else {
              req.pass = true;
              req.to = user.email;
              req.subject = "Codegurukul Password Change";
              req.email = "Your Current Password for Codegurukul has been changed";
              next();
            }
          });
        }
      });
    }
  });
};

exports.updateProfile = function(req, res) {
  User.findById(req.user._id, function(err, user) {
    if (err) res.status(400).send(err);
    else if (!user) {
      res.status(404).send(msg.unf);
    } else {
      if (req.body.email && validator.validate(req.body.email))
        user.email = req.body.email;
      else return res.status(400).send(msg.inem);
      user.mobile = req.body.mobile;
      user.profile.fullname = req.body.fullname;
      user.profile.location = req.body.location;
      user.profile.gender = req.body.gender;
      user.profile.dob = req.body.dob;
      user.profile.type = req.body.type;
      user.profile.website = req.body.website;
      user.profile.facebook = req.body.facebook;
      user.profile.twitter = req.body.twitter;
      user.profile.google = req.body.google;
      user.profile.github = req.body.github;
      user.profile.instagram = req.body.instagram;
      user.profile.linkedin = req.body.linkedin;
      user.profile.organization = req.body.organization;
      user.profile.college = req.body.college;
      user.profile.stream = req.body.stream;
      user.profile.experience = req.body.experience;
      user.profile.workDesc = req.body.workDesc;
      user.profile.skills.splice(0, user.profile.skills.length);
      for (var i = 0; i <= req.body.skills.length - 1; i++) {
        user.profile.skills.push(req.body.skills[i].text);
      };
      user.save(function(err) {
        if (err) res.status(400).send(err);
        res.json({
          message: 'Profile updated'
        });
      });
    }


  });
};