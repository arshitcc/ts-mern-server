import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { CustomRequest, IUser, User } from "../models/user.models";
import asyncHandler from "../utils/async-handler";
import { ApiResponse } from "../utils/api-response";
import { ACCESS_TOKEN_SECRET } from "../utils/env";
import { ApiError } from "../utils/api-error";

const authenticateUser = asyncHandler(
  async (req: CustomRequest, res: Response, next: NextFunction) => {
    const token =
      req.cookies?.accessToken ||
      req.headers.authorization?.replace("Bearer ", "");

    if (!token.trim()) {
      return res
        .status(400)
        .json(new ApiResponse(401, false, "Unauthorized Token"));
    }

    const decodedToken = jwt.verify(token, ACCESS_TOKEN_SECRET!) as {
      _id: string;
    };

    if (!decodedToken) {
      return res
        .status(400)
        .json(new ApiResponse(401, false, "Unauthorized Token"));
    }

    const user = await User.findById<IUser>(decodedToken._id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry -forgotPasswordToken -forgotPasswordExpiry",
    );

    if (!user) {
      return res
        .status(400)
        .json(new ApiResponse(404, false, "User not found"));
    }

    req.user = user;
    next();
  },
);

const verifyPermission = (roles: string[] = []) =>
  asyncHandler(
    async (req: CustomRequest, res: Response, next: NextFunction) => {
      if (!req.user?._id) {
        throw new ApiError(401, "Unauthorized request");
      }
      if (roles.includes(req.user.role)) {
        next();
      } else {
        throw new ApiError(403, "Unauthorized action");
      }
    },
  );

export const avoidInProduction = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    if (process.env.NODE_ENV === "development") {
      next();
    } else {
      throw new ApiError(
        403,
        "This service is only available in the local environment.",
      );
    }
  },
);

export { authenticateUser, verifyPermission };
