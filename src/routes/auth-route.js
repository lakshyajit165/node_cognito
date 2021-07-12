const express = require("express");
const router = express.Router();
const {
    signIn,
    signUp,
    confirmPassword,
    forgotPassword,
    logOut,
    getProtectedResource
} = require("../utilities/auth-utility");

router.post("/signin", signIn);
router.post("/signup", signUp);
router.post("/confirm_password", confirmPassword);
router.post("/forgot_password", forgotPassword);
router.get("/resource", getProtectedResource);
router.post("/logout", logOut);

module.exports = router;