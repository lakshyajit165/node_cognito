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
      let cognitoClient = new AWS.CognitoIdentityServiceProvider()
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
      return res.status(200).send({ message: "User logged in!" });
    } catch (err) {
      return res.status(500).send({ errorType: "SIGN_IN_ERROR", message: err.message || "Error signing in user!" });
    }
};

const signUp = async (req, res) => {
    let email = req.body.username;
    let cognitoClient;
    let temporaryHmac = generateTempPassword();
    let params = {
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
        cognitoClient = new AWS.CognitoIdentityServiceProvider();
        let createUserPromise = cognitoClient.adminCreateUser(params).promise();
        await createUserPromise;
        return res.status(200).send({ message: "Verification code sent!" });
    } catch (e) {
        console.error("Error from Cognito while creating User, starting rollback...");
        rollBackSignUp(email, cognitoClient);
        return res.status(500).send({ errorType: "Internal Server Error", message: e.message || "Error while signing up!"});
    }
};

const confirmPassword = async (req, res) => {
    try {
      let username = req.body.username;
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
      console.log(initAuthResponse);
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

const forgotPassword = (req, res) => {

};

const getProtectedResource = (req, res) => {
    // verify token here
    return res.status(200).send({ message: "Access granted!" });
};

const logOut = (req, res) => {

};

const generateTempPassword = () => {
    return generatePassword(8, false, /\d/);
};

const rollBackSignUp = async (emailId, cognitoClient) => {
    try {
        var params = {
            UserPoolId: userPoolId,
            Username: emailId
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
    getProtectedResource,
    logOut
}