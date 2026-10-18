import express from "express";
import {checkUrl} from "../controllers/urlController.js";
const router= express.Router();
router.post("/check-url",checkUrl);
export default router;