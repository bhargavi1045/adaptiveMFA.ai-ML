
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const JWT_EXPIRES_IN = '1h';

interface AuthRequest extends Request {
  user?: { username: string };
}

const mfaStore: Record<string, number> = {}; 

export const generateMFAChallenge = async (req: AuthRequest, res: Response) => {
  const username = req.body.username; 
  const { mfaMethod } = req.body;

  if (!username || !mfaMethod) {
    return res.status(400).json({ success: false, message: 'Username and MFA method required' });
  }

  const code = Math.floor(100000 + Math.random() * 900000);
  mfaStore[username] = code

  return res.status(200).json({ success: true, message: `MFA code generated`, mfaCode: code });
};


export const verifyMFA = async (req: AuthRequest, res: Response) => {
  const username = req.body.username;
  const { mfaCode } = req.body;

  if (!username) {
    return res.status(400).json({ success: false, message: 'username issue' });
  }
  if(!mfaCode){
    return res.status(400).json({ success: false,message : 'code issue'});
  }
  const expectedCode = mfaStore[username];
  if (!expectedCode) {
    return res.status(401).json({ success: false, message: 'code not found in storage' });
  }
  if (mfaCode !== expectedCode) {
    return res.status(401).json({ success :false, message : 'code not matched'});
  }

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  delete mfaStore[username];

  return res.status(200).json({ success: true, message: 'MFA verified', token });
};


export const invalidateMFA = async (req: AuthRequest, res: Response) => {
  const username = req.user?.username;
  if (!username) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  delete mfaStore[username];

  return res.status(200).json({ success: true, message: 'MFA invalidated' });
};
