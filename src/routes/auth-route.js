const express = require("express");
const router = express.Router();
const {
    signIn,
    signUp,
    confirmPassword,
    forgotPassword,
    logOut,
    getProtectedResource,
    confirmForgotPassword,
    testRoute,
} = require("../utilities/auth-utility");
const { validateToken } = require("../middlewares/auth-middleware");

router.post("/signin", signIn);
router.post("/signup", signUp);
router.post("/confirm_password", confirmPassword);
router.post("/forgot_password", forgotPassword);
router.post("/confirm_forgot_password", confirmForgotPassword);
router.get("/resource", [validateToken], getProtectedResource);
router.post("/logout", logOut);

module.exports = router;
