import mongoose, { Schema, Document } from "mongoose";

export interface IDevice extends Document {
  userId: string;
  deviceName: string;
  deviceOS: string;
  browser: string;
  lastUsed: Date;
  ipAddress: string;
}

const DeviceSchema = new Schema<IDevice>({
  userId: { type: String, required: true },
  deviceName: { type: String },
  deviceOS: { type: String },
  browser: { type: String },
  lastUsed: { type: Date, default: Date.now },
  ipAddress: { type: String },
});

export default mongoose.model<IDevice>("Device", DeviceSchema);
