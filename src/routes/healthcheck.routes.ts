import { Router } from "express";
import checkHealth from "../controllers/healthcheck.controllers";

const router = Router();

router.route("/").get(checkHealth);

export default router;
