import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import User, { IUser } from "../models/user.model";
import MFAChallenge from "../models/mfaChallenge.model";
import { createOTPChallenge, verifyOTPChallenge } from "../services/otp.service";
import { generateTOTPSecret, verifyTOTPCode } from "../services/totp.service";
import { generateFingerprintAuth, verifyFingerprintAuth } from "../services/fingerprint.service";
import { sendSMS } from "../services/sms.service";
import { createSessionToken } from "../services/jwt.service";

const JWT_SECRET = process.env.JWT_SECRET!;
const MFA_TOKEN_TTL = "5m";

interface MFAVerifyBody {
  mfaToken: string;
  code?: string;
  assertionResponse?: any;
}

export const generateMFAChallengeData = async (username: string, mfaMethod: string) => {
  const user = await User.findOne({ username });
  if (!user) throw new Error("User not found");

  let challengeData: any = {};

  switch (mfaMethod) {
    case "otp": {
      const otpCode = await createOTPChallenge(user.id);
      console.log(`OTP for ${user.username}: ${otpCode}`);
      challengeData = { message: "OTP sent to your email" };
      break;
    }
    case "sms": {
      if (!user.phone) throw new Error("User has no phone number");
      const smsCode = await createOTPChallenge(user.id);
      await sendSMS(user.phone, smsCode);
      challengeData = { message: "OTP sent via SMS" };
      break;
    }
    case "totp": {
      if (!user.totpSecret) {
        const secret = generateTOTPSecret(username);
        user.totpSecret = secret.base32;
        await user.save();
      }
      challengeData = { message: "Use your authenticator app" };
      break;
    }
    case "fingerprint": {
      challengeData = await generateFingerprintAuth(user);
      break;
    }
    default:
      throw new Error("Unsupported MFA method");
  }

  const mfaToken = jwt.sign(
    { userId: user.id, stage: "MFA_PENDING", method: mfaMethod },
    JWT_SECRET,
    { expiresIn: MFA_TOKEN_TTL }
  );

  return { mfaToken, challenge: challengeData };
};

export const generateMFAChallenge = async (req: Request, res: Response) => {
  try {
    const { username, mfaMethod } = req.body;
    if (!username || !mfaMethod) {
      return res.status(400).json({ message: "username and mfaMethod required" });
    }

    const { mfaToken, challenge } = await generateMFAChallengeData(username, mfaMethod);
    return res.json({ mfaToken, challenge });
  } catch (err: any) {
    console.error(err);
    return res.status(500).json({ message: err.message || "Internal server error" });
  }
};

export const verifyMFA = async (req: Request<{}, {}, MFAVerifyBody>, res: Response) => {
  const { mfaToken, code, assertionResponse } = req.body;
  if (!mfaToken) return res.status(400).json({ message: "mfaToken required" });

  let decoded: { userId: string; stage: string; method: string };
  try {
    decoded = jwt.verify(mfaToken, JWT_SECRET) as any;
  } catch {
    return res.status(401).json({ message: "Invalid or expired MFA token" });
  }

  if (decoded.stage !== "MFA_PENDING") return res.status(401).json({ message: "Invalid MFA token" });

  const user = await User.findById(decoded.userId);
  if (!user) return res.status(404).json({ message: "User not found" });

  let valid = false;

  switch (decoded.method) {
    case "otp":
    case "sms":
      if (!code) return res.status(400).json({ message: "Code required" });
      valid = await verifyOTPChallenge(user.id, code);
      break;
    case "totp":
      if (!code) return res.status(400).json({ message: "TOTP code required" });
      if (!user.totpSecret) return res.status(400).json({ message: "TOTP secret missing" });
      valid = verifyTOTPCode(user.totpSecret, code);
      break;
    case "fingerprint":
      if (!assertionResponse) return res.status(400).json({ message: "Assertion response required" });
      valid = await verifyFingerprintAuth(user, assertionResponse);
      break;
    default:
      return res.status(400).json({ message: "Unsupported MFA method" });
  }

  if (!valid) return res.status(401).json({ message: "MFA verification failed" });

  const sessionToken = createSessionToken(user, true);
  return res.json({ token: sessionToken });
};

export const invalidateMFA = async (req: Request<{}, {}, { userId: string }>, res: Response) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ message: "userId required" });

  await MFAChallenge.deleteMany({ userId });
  return res.json({ success: true });
};
