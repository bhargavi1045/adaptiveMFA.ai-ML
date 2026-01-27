import jwt, { SignOptions, Secret, JwtPayload } from "jsonwebtoken";
import type ms from "ms";
import { IUser } from "../models/user.model";

const JWT_SECRET: Secret = process.env.JWT_SECRET || "supersecretkey";

const JWT_EXPIRES_IN: ms.StringValue =
  (process.env.JWT_EXPIRES_IN as ms.StringValue) || "1h";

export interface SessionPayload {
  userId: string;
  username: string;
  mfaCompleted: boolean;
}

export const createSessionToken = (
  user: IUser,
  mfaCompleted = false
): string => {
  const payload: SessionPayload = {
    userId: user.id.toString(),
    username: user.username,
    mfaCompleted,
  };

  const options: SignOptions = {
    expiresIn: JWT_EXPIRES_IN,
  };

  return jwt.sign(payload, JWT_SECRET, options);
};

export const verifySessionToken = (token: string): SessionPayload | null => {
  try {
    return jwt.verify(token, JWT_SECRET) as JwtPayload & SessionPayload;
  } catch {
    return null;
  }
};
