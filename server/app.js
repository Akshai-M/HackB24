import express from "express";
import cookieparser from "cookie-parser";
import userRoutes from "./routes/user.routes.js"
import communityRoutes from "./routes/comunityRoutes.js"
import cors from "cors";
const app = express();
import { config } from "dotenv";
config({
    path: "./.env"
})

// console.log(process.env.FRONTEND_URL);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieparser())
app.use(cors({
    origin: process.env.FRONTEND_URL,
    origin: "http://localhost:5173",
    credentials: true
}));

// User Routes
app.use("/api/v1/users", userRoutes);
app.use("/api/v1/community", communityRoutes)
export default app;