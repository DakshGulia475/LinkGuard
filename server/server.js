import express from "express";
import dotenv from "dotenv";
import urlRoutes from "./routes/urlRoutes.js";
dotenv.config();

const app = express();

app.use(express.json());
app.use("/api",urlRoutes);
const PORT = process.env.PORT || 5000;

app.get("/health", (req, res) => {
    res.status(200).json({
        status: "ok",
        message: "LinkGuard backend is running"
    });
});

app.listen(PORT, () => {
    console.log(`LinkGuard server running on port ${PORT}`);
});
