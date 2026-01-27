import mongoose, { Schema, Document } from "mongoose";

export interface ILoginEvent extends Document {
  userId: string;
  success: boolean;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
}

const LoginEventSchema = new Schema<ILoginEvent>({
  userId: { type: String, required: true },
  success: { type: Boolean, required: true },
  ipAddress: { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now },
});

export default mongoose.model<ILoginEvent>("LoginEvent", LoginEventSchema);
