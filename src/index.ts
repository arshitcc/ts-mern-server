import express, { Request, Response } from "express";
import dotenv from "dotenv";
import cors from "cors";
import connectDB from "./db/db";
import cookieParser from "cookie-parser";
import morganMiddleware from "./loggers/morgan.logger";

dotenv.config({
  path: "./.env",
});

const PORT = process.env.PORT || 6969;

const app = express();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
  }),
);

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(morganMiddleware);

app.route("/").get((req: Request, res: Response) => {
  res.status(200).send("Server is running");
});

import healthCheckRouter from "./routes/healthcheck.routes";
import authRouter from "./routes/auth.routes";


app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/auth", authRouter);

connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch(() => {
    console.log("Error connecting to database");
  });
