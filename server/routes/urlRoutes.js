import express from "express";
import {checkUrl} from "../controllers/urlController.js";
import authMiddleware from "../middleware/authMiddleware.js";
const router= express.Router();
router.post("/check-url",authMiddleware,checkUrl);
export default router;