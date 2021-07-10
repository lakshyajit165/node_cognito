const express = require("express");
const router = express.Router();
const {
    signIn,
    signUp,
    logOut
} = require("../utilities/auth-utility");

router.post("/signin", signIn);
router.post("/signup", signUp);
router.post("/logout", logOut);

module.exports = router;