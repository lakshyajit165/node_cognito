const jsonwebtoken = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");
const AWS = require("aws-sdk");
const {
    port,
    accessKey,
    secretKey,
    region,
    userPoolId,
    appClientId
} = require("../../config");
AWS.config.update({
    region,
    accessKeyId: accessKey,
    secretAccessKey: secretKey,
});
const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const { getCognitoUserDetails, getEmailFromIdToken, getNewTokensUsingRefreshToken } = require("../utilities/auth-utility");
const CognitoUserPool = AmazonCognitoIdentity.CognitoUserPool;
const poolData = {
    UserPoolId: userPoolId,
    ClientId: appClientId
};
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

const jsonWebKeys = [  // from https://cognito-idp.<REGION>.amazonaws.com/<UserPoolId>/.well-known/jwks.json
    // include the json web keys from GITLAB ----------------------- (this is a reference for the author)
];


const validateToken = async (req, res, next) => {
    let idToken = req.headers["id_token"];
    let refreshToken = req.headers["refresh_token"];
    const header = decodeTokenHeader(idToken);  // {"kid":"XYZAAAAAAAAAAAAAAA/1A2B3CZ5x6y7MA56Cy+6abc=", "alg": "RS256"}
    const jsonWebKey = getJsonWebKeyWithKID(header.kid);
    const pem = jwkToPem(jsonWebKey);
    try {
        let email = verifyJsonWebTokenSignature(idToken, jsonWebKey);
        next(); // user might still be able to get here after logout...since refresh token is revoked but idtoken and accesstoken are still active (can maintain a token blacklist)
    } catch (err) {
        if(err.message === "jwt expired" || err.toString().split(":")[0] === "TokenExpiredError") {
        // try issuing new access and id token with the help of refresh token here and set the new tokens in the request AND response header(client collects the tokens from response header)...if that also throws an error(may be refresh token expired or any other error) send response to login again
            try {
                let newlyIssuedTokens = await getNewTokensUsingRefreshToken(refreshToken);
                // set the new tokens in request and response headers and proceed to access the resource
                if(newlyIssuedTokens 
                    && newlyIssuedTokens["AuthenticationResult"] 
                    && newlyIssuedTokens["AuthenticationResult"]["AccessToken"] 
                    && newlyIssuedTokens["AuthenticationResult"]["IdToken"]){
                        let newIdtoken = newlyIssuedTokens["AuthenticationResult"]["IdToken"];
                        let newAccessToken = newlyIssuedTokens["AuthenticationResult"]["AccessToken"];
                        req.headers["id_token"] = newIdtoken;
                        req.headers["access_token"] = newAccessToken;
                        res.setHeader("id_token", newIdtoken);
                        res.setHeader("access_token", newAccessToken);
                        next();
                }
            } catch (error) {
                console.log(error);
                return res.status(500).send({ message: error.message || "Error validating tokens. Please sign in again." });
            }
        } else {
            return res.status(500).send({ message: err.message || "Error validating tokens. Please sign in again." });
        }
    }
}

const decodeTokenHeader = (token) => {
    const [headerEncoded] = token.split('.');
    const buff = Buffer.from(headerEncoded, 'base64');
    const text = buff.toString('ascii');
    return JSON.parse(text);
}

const getJsonWebKeyWithKID = (kid) => {
    for (let jwk of jsonWebKeys) {
        if (jwk.kid === kid) {
            return jwk;
        }
    }
    return null
}

const verifyJsonWebTokenSignature = (token, jsonWebKey) => {
    const pem = jwkToPem(jsonWebKey);
    try {
        const { email } = jsonwebtoken.verify(token, pem, {algorithms: ['RS256']});
        return email;
    } catch(err) {
        throw err;
    }
}

module.exports = {
    validateToken
}