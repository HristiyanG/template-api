const APIError = require('./../api-error');

class Authentication {

    /**
     * Example of Extensible Service Proxy which validates the token on behalf of the API and forwards all headers it receives,
     * including the original authorization header, to the API.
     * In addition, ESP sends the authentication result in the X-Endpoint-API-UserInfo header to the API. This header is base64url encoded.
     */
    static async retrieveAuthenticatedUserId(req, res, next) {
        const authenticatedResultsAsBase64 = req.headers['x-endpoint-api-userinfo'];
        if (!authenticatedResultsAsBase64) {
            return next(new APIError(401, 'Unauthorized. No user info header provided.'))
        }
        const userInfoBuff = Buffer.from(authenticatedResultsAsBase64, 'base64');
        const userInfo = JSON.parse(userInfoBuff.toString('ascii'));

        res.locals.userId = userInfo.id;
        next();
    }

}

module.exports = Authentication;