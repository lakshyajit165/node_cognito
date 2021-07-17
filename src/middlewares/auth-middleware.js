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

// const validateTokens = async (req, res) => {
//     let idToken = req.headers["id_token"];
//     let accessToken = req.headers["access_token"];
//     let refreshToken = req.headers["refresh_token"];
//     let userDetails;
//     let cognitoClient = new AWS.CognitoIdentityServiceProvider();

//     if(!idToken || !accessToken || !refreshToken)
//         return res.status(400).send({ message: "Invalid headers" });
//     try {
//         userDetails = await getCognitoUserDetails(getEmailFromIdToken(idToken), cognitoClient);
//         console.log(userDetails);
//     } catch (err) {
//         return res.status(500).send({ message: err.message || "Error while verifying user details" });
//     }
      

// };

const jsonWebKeys = [  // from https://cognito-idp.us-west-2.amazonaws.com/<UserPoolId>/.well-known/jwks.json
    {
        "alg": "RS256",
        "e": "AQAB",
        "kid": "tMBPkwJLHq7d01ASyfobkNEDCMuBtw/0r6hZqyDPqrg=",
        "kty": "RSA",
        "n": "vqI_C4hJUxtkmNiTVMBqtALe9RcwJGp7ogdFzkrCofmtZpLyt4KhPZMUSReOhRXZBsDXHcsp9oKOJpqHLyhm64xA3g4L0vbiX7wM1eTr-_E2mSkdXxUmDU_IpTjUmyVVKw5HGSZmbKUv_5Stt148k7QGQ1F4T3R_2YQdQwf4tVJKsE5PEcZ7kKZOS59hkRDPlN0-TfKuCVsoOLGV0H6sRrcKGqi2F4sn0Jvvz0w3msKm4jBLMi8T6wGSUH83k21rOchKMkZJjNt9WMv_5EE4hb3vC-aZH38kKnuOp78rkgzJ1HDemFSJdNo176jMoH0jnrNuMn9VpKFjblXs_VJYpw",
        "use": "sig"
      },
      {
        "alg": "RS256",
        "e": "AQAB",
        "kid": "/sYQSxKQ/ufjkEgTUHq7d/LqrDBRnWy/L244TrF8KwI=",
        "kty": "RSA",
        "n": "wFnJKhyXPzDJU8Wl-I9T27srTHxvn2fi-_mMbeLemix1E_lLMH0camuey6orgDxRRxGSwf5wsaZiyUZO7DCgigTf_TIVks5PKfDbrTHcxpWS_KDQrytdosJPgzjSAX7j8Mj42JcqnyqLS5INyjB18epYTKWNpKbl2gJg3e9hnWT2BTJmlJidRBZRS0qZVw7vpA3vROGDHhNDIKnl6E5xcHtPZ0k3m7lKp6inHaEDv5URp8FZcLMjyhr7XjAqLgIBiUx6azz-u9Y7e-8eBUNljhPWMUCCoN5N14w9P4N4d-vBcgmzYZ6opAVCdo9uJk2ewGwvNZ-AIHroNQRGRgbwbQ",
        "use": "sig"
      }
]


const validateToken = async (req, res, next) => {
    let idToken = req.headers["id_token"];
    let refreshToken = req.headers["refresh_token"];
    const header = decodeTokenHeader(idToken);  // {"kid":"XYZAAAAAAAAAAAAAAA/1A2B3CZ5x6y7MA56Cy+6abc=", "alg": "RS256"}
    const jsonWebKey = getJsonWebKeyWithKID(header.kid);
    const pem = jwkToPem(jsonWebKey);
    try {
        let decodedToken = verifyJsonWebTokenSignature(idToken, jsonWebKey);
        console.log(decodedToken);
        next();
    } catch (err) {
        if(err.message === "jwt expired" || err.toString().split(":")[0] === "TokenExpiredError") {
        // try issuing new access and id token with the help of refresh token here and set the new tokens in the request AND response header(client collects the tokens from response header)...if that also throws an error(may be refresh token expired or any other error) send response to login again
            try {
                let newlyIssuedTokens = await getNewTokensUsingRefreshToken(refreshToken);
                console.log(newlyIssuedTokens);
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
                return res.status(500).send({ message: "Error validating tokens. Please sign in again." });
            }
        } else {
            return res.status(500).send({ message: "Error validating tokens. Please sign in again." });
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
        const { decodedToken } = jsonwebtoken.verify(token, pem, {algorithms: ['RS256']});
        return decodedToken;
    } catch(err) {
        throw err;
    }
}

module.exports = {
    validateToken
}