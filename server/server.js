import express from "express";
import dotenv from "dotenv";
import {connectDB} from "./config/db.js";
import urlRoutes from "./routes/urlRoutes.js";
import authRoutes from "./routes/authRoutes.js";
dotenv.config();

const app = express();

app.use(express.json());
app.use("/api",urlRoutes);
app.use("/api/auth",authRoutes);
app.use("/api/auth",authRoutes);
const PORT = process.env.PORT || 5000;

app.get("/health", (req, res) => {
    res.status(200).json({
        status: "ok",
        message: "LinkGuard backend is running"
    });
});
async function startServer(){
    try{
      await connectDB(process.env.MONGODB_URI);
      console.log("mongoDB connection successfull");
       app.listen(PORT, () => {
    console.log(`LinkGuard server running on port ${PORT}`);
});
    }
    catch(error){
        console.log(error);
        process.exit(1);
    }
}
   startServer();

