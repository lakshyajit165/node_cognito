const dotenv = require("dotenv");
dotenv.config();
module.exports = {
  port: process.env.PORT,
  accessKey: process.env.ACCESSKEY,
  secretKey: process.env.SECRETKEY,
  region: process.env.REGION,
  userPoolId: process.env.USER_POOL_ID,
  appClientId: process.env.APP_CLIENT_ID
};
