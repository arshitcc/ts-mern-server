import { validationResult } from "express-validator";
import { CustomRequest } from "../models/user.models";
import { NextFunction, Request, Response } from "express";
import { ApiError } from "../utils/api-error";

export const validate = (
  req: Request | CustomRequest,
  res: Response,
  next: NextFunction,
) => {
  const errors = validationResult(req);

  if (errors.isEmpty()) {
    return next();
  }

  throw new ApiError(
    400,
    "Validation Failed",
    errors.array(),
    false,
    errors.array(),
  );
};
