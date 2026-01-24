import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import User, { IUser } from '../models/user.model';

import BehaviorAgent, { BehaviorFeatures } from '../agents/behavior.agent';
import ContextAgent, { ContextFeatures, LoginContext } from '../agents/context.agent';
import RiskAgent, { RiskFactors } from '../agents/risk.agent';
import FraudAgent, { FraudIndicators } from '../agents/fraud.agent';
import DecisionAgent, { MFADecision } from '../agents/decision.agent';

interface AuthRequest extends Request {
  user?: { username: string };
}

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const JWT_EXPIRES_IN = '1h';

export const register = async (req: Request, res: Response) => {
  try {
    const { username, email, password, mfaEnabled } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'Username, email, and password required' });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Username or email already exists' });
    }

    const newUser = new User({ username, email, password, mfaEnabled: !!mfaEnabled });
    await newUser.save();

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: { username: newUser.username, email: newUser.email, mfaEnabled: newUser.mfaEnabled }
    });
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const loginContext: LoginContext = {
      ipAddress: req.body.ipAddress || req.ip || '0.0.0.0',
      deviceId: req.body.deviceId || 'unknown_device',
      userAgent: req.headers['user-agent'] || 'unknown',
      timestamp: new Date(),
      geolocation: req.body.geolocation,
    };

    const contextData: ContextFeatures = {
      new_device: req.body.newDevice ? 1 : 0,
      ip_change: req.body.ipChange ? 1 : 0,
      login_hour: new Date().getHours(),
      is_weekend: [0, 6].includes(new Date().getDay()) ? 1 : 0,
      is_night: [0, 1].includes(new Date().getHours()) ? 1 : 0,
      browser_automation_detected: req.body.automationDetected ? 1 : 0,
    };

    const behaviorData: BehaviorFeatures = {
      keystroke_interval_ms: req.body.keystrokeInterval || 200,
      mouse_speed_px_s: req.body.mouseSpeed || 500,
      session_duration_s: req.body.sessionDuration || 60,
      click_rate: req.body.clickRate || 1,
      keystroke_variance: req.body.keystrokeVariance,
      pages_visited: req.body.pagesVisited,
      automation_detected: req.body.automationDetected ? 1 : 0,
    };

    const fraudIndicators: FraudIndicators = {
      loginFrequency24h: req.body.loginFrequency24h || 1,
      uniqueIPs24h: req.body.uniqueIPs24h || 1,
      failedAttemptsRatio: req.body.failedAttemptsRatio || 0,
      deviceConsistencyScore: req.body.deviceConsistencyScore || 1,
      impossibleTravel: req.body.impossibleTravel || false,
      automationDetected: req.body.automationDetected || false,
      countryChanges24h: req.body.countryChanges24h || 0,
    };

    const userHistory = req.body.userHistory || [];

    const behaviorAgent = new BehaviorAgent();
    const contextAgent = new ContextAgent();
    const fraudAgent = new FraudAgent();
    const riskAgent = new RiskAgent();
    const decisionAgent = new DecisionAgent();

    const behaviorAnalysis = await behaviorAgent.analyze(behaviorData, undefined, userHistory);
    const contextAnalysis = await contextAgent.analyze(contextData, loginContext, undefined, userHistory);
    const fraudAnalysis = await fraudAgent.analyze(fraudIndicators, undefined, userHistory);

    const riskFactors: RiskFactors = {
      behaviorScore: behaviorAnalysis.anomalyScore,
      contextScore: contextAnalysis.riskProbability,
      fraudScore: fraudAnalysis.fraudProbability,
      accountHistoryScore: req.body.accountHistoryScore || 0.5,
    };

    const riskAnalysis = await riskAgent.analyze(riskFactors, undefined, {
      failedLoginAttempts: req.body.failedLoginAttempts || 0,
      accountAge: req.body.accountAge || 365,
      totalLogins: req.body.totalLogins || 50,
      averageRiskScore: req.body.averageRiskScore || 0.5,
    });

    const decision: MFADecision = await decisionAgent.decide({
      behaviorAnalysis,
      contextAnalysis,
      fraudAnalysis,
      riskAnalysis,
      userProfile: {
        mfaEnabled: user.mfaEnabled,
        isTrustedDevice: req.body.isTrustedDevice || false,
        accountAge: req.body.accountAge || 365,
      },
    });


    let token: string | null = null;
    if (!decision.mfaRequired) {
      token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    }

    return res.status(200).json({
      success: true,
      decision,
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

export const logout = async (_req: AuthRequest, res: Response) => {
  return res.status(200).json({ success: true, message: 'Logged out successfully' });
};

export const status = async (req: AuthRequest, res: Response) => {
  return res.status(200).json({ success: true, authenticated: !!req.user, user: req.user || null });
};
