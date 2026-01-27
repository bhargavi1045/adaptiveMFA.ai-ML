import speakeasy from "speakeasy";

export const generateTOTPSecret = (username: string) =>
  speakeasy.generateSecret({ name: `AdaptiveMFA (${username})` });

export const verifyTOTPCode = (secret: string, token: string) =>
  speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token,
    window: 1,
  });
