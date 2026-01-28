import { Request, Response } from "express";
import User from "../models/user.model";
import { createSessionToken } from "../services/jwt.service";
import { generateMFAChallengeData } from "./mfa.controller";
import { sendPushNotification } from "../server";
import LoginEvent from "../models/loginEvent.model";
import Device from "../models/device.model";
import { geographicalRiskService } from "../services/geographical-risk.service";

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
    const { username, password, mfaMethod, deviceName, browser, deviceOS } = req.body;
    if (!username || !password)
      return res.status(400).json({ success: false, message: 'Username and password required' });

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const isMatch = await user.comparePassword(password);

    // Get client IP and user agent
    //const ip = getClientIP(req);
    const ip = req.body.ip || req.ip;
    const userAgent = req.headers["user-agent"] || "Unknown";

    // ✅ NEW: Assess geographical risk
    const riskAssessment = await geographicalRiskService.assessGeographicalRisk(
      user._id.toString(),
      ip,
      true
    );

    console.log('🌍 Risk Assessment:', {
      score: riskAssessment.riskScore,
      level: riskAssessment.riskLevel,
      factors: riskAssessment.riskFactors
    });

    // ✅ NEW: Check if should block
    if (riskAssessment.shouldBlock) {
      await geographicalRiskService.saveLoginHistory(
        user._id.toString(),
        ip,
        userAgent,
        false,
        riskAssessment,
        'Blocked due to high risk'
      );

      await LoginEvent.create({
        userId: user.id,
        success: false,
        ipAddress: ip,
        userAgent,
      });

      return res.status(403).json({
        success: false,
        error: 'Login blocked due to security concerns',
        riskLevel: riskAssessment.riskLevel
      });
    }

    if (user.mfaEnabled || riskAssessment.requiresMFA) {
      const { mfaToken, challenge } = await generateMFAChallengeData(username, mfaMethod || 'otp');

      await geographicalRiskService.saveLoginHistory(
        user._id.toString(),
        ip,
        userAgent,
        true,
        riskAssessment,
        undefined,
        true,
        false
      );

      await LoginEvent.create({
        userId: user.id,
        success: false,
        ipAddress: ip,
        userAgent,
      });

      sendPushNotification(user.id, "mfa_challenge", { challenge, mfaMethod });

      return res.json({
        success: true,
        decision: { mfaRequired: true },
        mfaToken,
        challenge,
        riskAssessment: {
          score: riskAssessment.riskScore,
          level: riskAssessment.riskLevel
        }
      });
    }

    // ✅ NEW: Save successful login
    await geographicalRiskService.saveLoginHistory(
      user._id.toString(),
      ip,
      userAgent,
      true,
      riskAssessment
    );

    const sessionToken = createSessionToken(user, true);

    await LoginEvent.create({
      userId: user.id,
      success: isMatch,
      ipAddress: ip,
      userAgent,
    });

    if (deviceName && browser && deviceOS) {
      const deviceExists = await Device.findOne({ userId: user.id, deviceName, ipAddress: ip });
      if (!deviceExists) {
        await Device.create({ userId: user.id, deviceName, ipAddress: ip, browser, deviceOS });
        sendPushNotification(user.id, "new_device", { deviceName });
      }
    }

    return res.json({
      success: true,
      decision: { mfaRequired: false },
      token: sessionToken,
      riskAssessment: {
        score: riskAssessment.riskScore,
        level: riskAssessment.riskLevel
      }
    });

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

// Helper to get real client IP
function getClientIP(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const ips = (forwarded as string).split(',');
    return ips[0].trim();
  }
  return req.socket.remoteAddress || req.ip || '127.0.0.1';
}
