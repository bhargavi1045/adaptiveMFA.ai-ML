import mongoose, { Schema, Document } from "mongoose";

export interface IMFAChallenge extends Document {
  userId: string;
  type: "otp" | "sms" | "totp" | "webauthn";
  codeHash?: string;
  expiresAt: Date;
  metadata?: Record<string, any>;
}

const MFASchema = new Schema<IMFAChallenge>({
  userId: { type: String, required: true, index: true },
  type: { type: String, required: true },
  codeHash: { type: String },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }, 
  },
  metadata: { type: Schema.Types.Mixed },
});

export default mongoose.model<IMFAChallenge>("MFAChallenge", MFASchema);
