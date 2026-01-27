import { Fido2Lib } from "fido2-lib";
import base64url from "base64url";
import MFAChallenge from "../models/mfaChallenge.model";
import { IUser } from "../models/user.model";

const rpID = process.env.RP_ID || "localhost";
const origin = process.env.FRONTEND_ORIGIN || "http://localhost:3000";

const fido2 = new Fido2Lib({
  rpId: rpID,
  rpName: "AdaptiveMFA",
  challengeSize: 64,
});


const bufferToArrayBuffer = (buf: Buffer): ArrayBuffer => {
  return Uint8Array.from(buf).buffer;
};

export const generateFingerprintAuth = async (user: IUser) => {
  const options = await fido2.assertionOptions();

  await MFAChallenge.create({
    userId: user.id,
    type: "webauthn",
    metadata: { challenge: options.challenge },
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
  });

  options.allowCredentials = user.credentials.map((c) => ({
    id: bufferToArrayBuffer(base64url.toBuffer(c.id)),
    type: "public-key" as const,
    transports: ["internal"],
  }));

  return options;
};

export const verifyFingerprintAuth = async (
  user: IUser,
  assertionResponse: any
) => {
  const challengeEntry = await MFAChallenge.findOne({
    userId: user.id,
    type: "webauthn",
  });

  if (!challengeEntry?.metadata?.challenge) {
    throw new Error("Challenge expired or invalid");
  }

  const verification = await fido2.assertionResult(assertionResponse, {
    challenge: challengeEntry.metadata.challenge,
    origin,
    factor: "either",
    publicKey: user.credentials[0].publicKey,
    prevCounter: user.credentials[0].counter,
    userHandle: user.id.toString(),
  });

  user.credentials[0].counter = verification.authnrData.get("counter");
  await user.save();
  await challengeEntry.deleteOne();

  return true;
};
