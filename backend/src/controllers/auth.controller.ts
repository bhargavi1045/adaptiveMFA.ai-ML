import { Request, Response } from "express";
import User from "../models/user.model";
import { createSessionToken } from "../services/jwt.service";
import { generateMFAChallengeData } from "./mfa.controller";
import { sendPushNotification } from "../server"

interface AuthRequest extends Request {
  user?: { username: string };
}

export const register = async (req: Request, res: Response) => {
  try {
    const { username, email, password, mfaEnabled, phone } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ success: false, message: 'Username, email, and password required' });

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) return res.status(400).json({ success: false, message: 'Username or email already exists' });

    const newUser = new User({ username, email, password, phone, mfaEnabled: !!mfaEnabled });
    await newUser.save();

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: { username: newUser.username, email: newUser.email, mfaEnabled: newUser.mfaEnabled }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { username, password, mfaMethod } = req.body;
    if (!username || !password)
      return res.status(400).json({ success: false, message: 'Username and password required' });

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    if (user.mfaEnabled) {
      const { mfaToken, challenge } = await generateMFAChallengeData(username, mfaMethod || 'otp');
      sendPushNotification(user.id, "mfa_challenge", { challenge, mfaMethod });
      return res.json({
        success: true,
        decision: { mfaRequired: true },
        mfaToken,
        challenge
      });
    } else {
      const sessionToken = createSessionToken(user, true);
      return res.json({
        success: true,
        decision: { mfaRequired: false },
        token: sessionToken
      });
    }

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

export const logout = async (_req: AuthRequest, res: Response) => {
  return res.json({ success: true, message: 'Logged out successfully' });
};

export const status = async (req: AuthRequest, res: Response) => {
  return res.json({ success: true, authenticated: !!req.user, user: req.user || null });
};
