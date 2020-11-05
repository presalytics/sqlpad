const passport = require('passport');
const PassportJwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const appLog = require('../lib/app-log');
const jwksRsa = require('jwks-rsa');
const fetch = require('node-fetch');

/**
 * Adds JWT Service Token auth strategy if configured
 *
 * JWT auth is a fallback authentication method for service tokens when no
 * authenticated session in passport created by other strategies like Local
 * Auth, OAuth or SAML
 * @param {object} config
 * @param 
 */


function enablePresalyticsJWTToken(config) {
   
    appLog.info('Enabling Presalytics JWT authentication strategy.');
        
    var JwtStrategy = require('passport-jwt').Strategy,
        ExtractJwt = require('passport-jwt').ExtractJwt;
    var opts = {}
    opts.secretOrKeyProvider = jwksRsa.passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://login.presalytics.io/.well-known/jwks.json`
    });
    opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
    opts.issuer = 'https://login.presalytics.io/';
    opts.audience = 'https://api.presalytics.io/';
    passport.use(new PassportJwtStrategy(
        {
            passReqToCallback: true,
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKeyProvider: jwksRsa.passportJwtSecret({
                cache: true,
                rateLimit: true,
                jwksRequestsPerMinute: 5,
                jwksUri: `https://login.presalytics.io/.well-known/jwks.json`
            }),
            issuer: 'https://login.presalytics.io/',
            audience: 'https://api.presalytics.io/'
        },
        async function (req, jwt_payload, done) {
          try {
            const { models } = req;
            const user = await models.users.findOneByPresalyticsUserId(
                jwt_payload["https://api.presalytics.io/api_user_id"]
            );
            if (!user) {
                let token = req.get('authorization');
                let userInfo = await fetch("https://login.presalytics.io/userinfo", {
                    headers: {
                        'Authorization': token
                    }
                }).then( async (resp) => {
                    if (resp.ok) {
                        return await resp.json();
                    } else {
                        let msg = await resp.text();
                        throw new Error(msg);
                    }
                });
                let isBuilder = jwt_payload["https://api.presalytics.io/roles"].includes("builder");
                let name;
                if (userInfo.nickname) {
                    name = userInfo.nickname;
                 } else {
                    name = userInfo.given_name + " " + userInfo.family_name;
                 } 
                user = models.users.create({
                    email: userInfo.email,
                    role: (isBuilder) ? 'admin' : 'editor',
                    name: name,
                    syncAuthRole: true,
                    presalyticsUserId: jwt_payload["https://api.presalytics.io/api_user_id"]
                });
            }
            return done(null, user);
          } catch (error) {
            done(error);
          }
        })
    )
}

module.exports = enablePresalyticsJWTToken;
