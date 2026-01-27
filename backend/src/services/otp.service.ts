import bcrypt from "bcryptjs";
import MFAChallenge from "../models/mfaChallenge.model";

const OTP_TTL_MS = 5 * 60 * 1000;

export const createOTPChallenge = async (userId: string) => {
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const hash = await bcrypt.hash(code, 10);

  await MFAChallenge.create({
    userId,
    type: "otp",
    codeHash: hash,
    expiresAt: new Date(Date.now() + OTP_TTL_MS),
  });

  return code;
};

export const verifyOTPChallenge = async (userId: string, code: string) => {
  const challenge = await MFAChallenge.findOne({ userId, type: "otp" });
  if (!challenge) return false;

  const valid = await bcrypt.compare(code, challenge.codeHash!);
  if (valid) await challenge.deleteOne();

  return valid;
};
