import { Request } from 'express';

export interface JwtUser {
  username: string;
}

export interface AuthRequest extends Request {
  user?: JwtUser;
}
