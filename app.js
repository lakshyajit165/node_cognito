const express = require("express");
const cors = require("cors");
const app = express();


const authRoutes = require("./src/routes/auth-route");
app.use(express.json());
app.use(cors());
app.use(authRoutes);    

app.listen(process.env.PORT, function () {
    console.log(`Server is listening on Port: ${process.env.PORT}`);
});