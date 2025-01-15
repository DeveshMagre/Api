require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const connectDB = require("./config/db");
const authRoutes = require("./routes/auth");

const app = express();
const PORT = process.env.PORT || 5000;


app.use(express.json());
app.use(helmet()); 

connectDB();

app.use("/api/auth", authRoutes);

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
