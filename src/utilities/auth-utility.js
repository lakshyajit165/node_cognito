const AWS = require("aws-sdk");
const generatePassword = require("password-generator");
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
const CognitoUserPool = AmazonCognitoIdentity.CognitoUserPool;
const poolData = {
    UserPoolId: userPoolId,
    ClientId: appClientId
};
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    
const signIn = async (req, res) => {
    let email = req.body.email;
    let password = req.body.password;
    try {
      let cognitoClient = new AWS.CognitoIdentityServiceProvider();
      let signInResponse = await cognitoClient.adminInitiateAuth({
        AuthFlow: 'ADMIN_NO_SRP_AUTH',
        ClientId: appClientId,
        UserPoolId: userPoolId,
        AuthParameters: {
          USERNAME: email,
          PASSWORD: password
        }
      }).promise();
      // console.log(signInResponse);  // can send the tokens to frontend from here(after creating the response object)
      // set idtoken, accesstoken and refreshtoken in response headers
      res.setHeader("access_token", signInResponse["AuthenticationResult"]["AccessToken"]);
      res.setHeader("id_token", signInResponse["AuthenticationResult"]["IdToken"]);
      res.setHeader("refresh_token", signInResponse["AuthenticationResult"]["RefreshToken"]);
      return res.status(200).send({ message: "User logged in!" });
    } catch (err) {
      return res.status(500).send({ errorType: "SIGN_IN_ERROR", message: err.message || "Error signing in user!" });
    }
};

// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html && 
// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminDeleteUser.html
const signUp = async (req, res) => {
    let email = req.body.email;
    let cognitoClient = new AWS.CognitoIdentityServiceProvider();
    let temporaryHmac = generateTempPassword();
    let paramsForCreatingUser = {
      UserPoolId: userPoolId,
      Username: email,
      DesiredDeliveryMediums: ["EMAIL"],
      TemporaryPassword: temporaryHmac,
      UserAttributes: [
        {
          Name: "email",
          Value: `${email}`,
        },
        {
          Name: "email_verified",
          Value: "true",
        },
      ],
    };
    // admingetuser -> if user exists and state is 'FORCE_CHANGE_PASSWORD' delete the user entry(and verification code will be sent again)
    try {
        let userDetails = await getCognitoUserDetails(email, cognitoClient);
        if(userDetails && userDetails["UserStatus"] === "FORCE_CHANGE_PASSWORD")
            await deleteCognitoUser(email, cognitoClient);
    } catch (err) {
        if(err.code === "UserNotFoundException")
            console.info("New User signing up!");
        else
            console.error(error);
    }
   
    try {
        let createUserPromise = cognitoClient.adminCreateUser(paramsForCreatingUser).promise();
        await createUserPromise;
        return res.status(200).send({ message: "Verification code sent!" });
    } catch (e) {
        console.error("Error from Cognito while creating User, starting rollback...");
        deleteCognitoUser(email, cognitoClient);
        return res.status(500).send({ errorType: "Internal Server Error", message: e.message || "Error while signing up!"});
    }
};

// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminRespondToAuthChallenge.html
const confirmPassword = async (req, res) => {
    try {
      let username = req.body.email;
      let password = req.body.password;
      let verificationCode = req.body.verification_code;
      username = username.toLowerCase();
      let cognitoClient = new AWS.CognitoIdentityServiceProvider();
      const initAuthResponse = await cognitoClient.adminInitiateAuth({
        AuthFlow: 'ADMIN_NO_SRP_AUTH',
        ClientId: appClientId,
        UserPoolId: userPoolId,
        AuthParameters: {
          USERNAME: username,
          PASSWORD: verificationCode
        }
      }).promise();
      if (initAuthResponse.ChallengeName === 'NEW_PASSWORD_REQUIRED') {
        await cognitoClient.adminRespondToAuthChallenge({
          ChallengeName: 'NEW_PASSWORD_REQUIRED',
          ClientId: appClientId,
          UserPoolId: userPoolId,
          ChallengeResponses: {
            USERNAME: username,
            NEW_PASSWORD: password,
          },
          Session: initAuthResponse.Session
        }).promise();
        return res.status(200).send({ message: "SignUp complete!" });
      }
      return res.status(500).send({ message: "An error occured!" });
    } catch (err) {
        return res.status(500).send({ errorType: "password_set_error", message: err.message || "Error setting password" });
    }
};

// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
const forgotPassword = async (req, res) => {
    let email = req.body.email;
    let cognitoClient = new AWS.CognitoIdentityServiceProvider();
    let params = {
      ClientId: appClientId, /* required */
      Username: email, /* required */
    };
    try {
      await cognitoClient.forgotPassword(params).promise();
      return res.status(200).send({ message: "Verification code sent for password reset!" });
    } catch(err) {
      console.log(err);
      return res.status(500).send({ errorType: "PASSWORD_RESET_ERROR", message: err.message || "Error sending verification code for password reset" });
    }
};

// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html
const confirmForgotPassword = async (req, res) => {
    let email = req.body.email;
    let confirmationCode = req.body.confirmation_code;
    let password = req.body.password;
    let cognitoClient = new AWS.CognitoIdentityServiceProvider();
    let params = {
      ClientId: appClientId,
      ConfirmationCode: confirmationCode,
      Password: password,
      Username: email
    };
    try {
      await cognitoClient.confirmForgotPassword(params).promise();
      return res.status(200).send({ message: "Password reset successful!" });
    } catch(err) {
      console.log(err);
      return res.status(500).send({ errorType: "PASSWORD_RESET_ERROR", message: err.message || "Error resetting password!" });
    }

};

const getProtectedResource = (req, res) => {
    // check if idtoken is expired but refresh token is valid, request a new token using this refresh token and send it in response headers
    // if refresh token is also expired, send appropriate response indicating -> user has to login again
    // else check if the token are valid from cognito's end(user might have logged out - invalidating the tokens)
    return res.status(200).send({ message: "Access granted!" });
};

// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminUserGlobalSignOut.html
const logOut = async (req, res) => {
    let idToken = req.headers["id_token"];
    let email = getEmailFromIdToken(idToken);
    let cognitoClient = new AWS.CognitoIdentityServiceProvider();
    if(!email)
        return res.status(500).send({ message: "Error extracting email from token" });
    let params = {
        UserPoolId: userPoolId, /* required */
        Username: email /* required */
    };
    try {
        await cognitoClient.adminUserGlobalSignOut(params).promise();
        return res.status(200).send({ message: "User logged out!" });
    } catch(err) {
        return res.status(500).send({ message: err.message || "Error logging out user. Please try again." });
    }
};

const getCognitoUserDetails = async (email, cognitoClient) => {
    let paramsForGettingUserDetails = {
      UserPoolId: userPoolId,
      Username: email
    };
    try {
        let userDetails = await cognitoClient.adminGetUser(paramsForGettingUserDetails).promise();
        return userDetails;
    } catch(err) {
        throw err;
    }

};

const getNewTokensUsingRefreshToken = async (refreshToken) => {
    try {
        let cognitoClient = new AWS.CognitoIdentityServiceProvider();
        let refreshTokenResponse = await cognitoClient.adminInitiateAuth({
          AuthFlow: 'REFRESH_TOKEN_AUTH',
          ClientId: appClientId,
          UserPoolId: userPoolId,
          AuthParameters: {
            REFRESH_TOKEN: refreshToken
          }
        }).promise();
        return refreshTokenResponse; // can send the tokens to frontend from here(after creating the response object)
    } catch (err) {
        throw err;
    }
};

const generateTempPassword = () => {
    return generatePassword(8, false, /\d/);
};

const getEmailFromIdToken = (idToken) => {
    let base64Payload = idToken.split(".")[1];
    let idTokenPayload = Buffer.from(base64Payload, "base64");
    let decodedPayload = JSON.parse(idTokenPayload.toString());
    let email = decodedPayload && decodedPayload.email;
    return email;
};

const deleteCognitoUser = async (email, cognitoClient) => {
    try {
        let params = {
            UserPoolId: userPoolId,
            Username: email
        };
        let deleteUserPromise = cognitoClient.adminDeleteUser(params).promise();
        await deleteUserPromise;
    } catch (e) {
        console.error("Exception while deleting user : " + emailId + " from Cognito. " + e);
    }
};

module.exports = {
    signIn, 
    signUp,
    confirmPassword,
    forgotPassword,
    confirmForgotPassword,
    getProtectedResource,
    getCognitoUserDetails,
    getEmailFromIdToken,
    getNewTokensUsingRefreshToken,
    logOut
}