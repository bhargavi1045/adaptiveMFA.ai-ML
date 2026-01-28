import mongoose, { Schema, Document } from 'mongoose';

export interface ILoginHistory extends Document {
  userId: mongoose.Types.ObjectId;
  ip: string;
  country: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  timezone: string;
  isVPN: boolean;
  isProxy: boolean;
  userAgent: string;
  deviceType: 'mobile' | 'tablet' | 'desktop' | 'unknown';
  browser: string;
  os: string;
  success: boolean;
  failureReason?: string;
  mfaRequired: boolean;
  mfaCompleted: boolean;
  riskScore: number;
  riskFactors: string[];
  timestamp: Date;
}

const LoginHistorySchema = new Schema<ILoginHistory>({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  ip: {
    type: String,
    required: true
  },
  country: {
    type: String,
    required: true
  },
  region: {
    type: String,
    required: true
  },
  city: {
    type: String,
    required: true
  },
  latitude: {
    type: Number,
    required: true
  },
  longitude: {
    type: Number,
    required: true
  },
  timezone: {
    type: String,
    required: true
  },
  isVPN: {
    type: Boolean,
    default: false
  },
  isProxy: {
    type: Boolean,
    default: false
  },
  userAgent: {
    type: String,
    required: true
  },
  deviceType: {
    type: String,
    enum: ['mobile', 'tablet', 'desktop', 'unknown'],
    default: 'unknown'
  },
  browser: {
    type: String,
    default: 'unknown'
  },
  os: {
    type: String,
    default: 'unknown'
  },
  success: {
    type: Boolean,
    required: true
  },
  failureReason: {
    type: String
  },
  mfaRequired: {
    type: Boolean,
    default: false
  },
  mfaCompleted: {
    type: Boolean,
    default: false
  },
  riskScore: {
    type: Number,
    required: true,
    min: 0,
    max: 100
  },
  riskFactors: [{
    type: String
  }],
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  }
});

// Indexes for efficient queries
LoginHistorySchema.index({ userId: 1, timestamp: -1 });
LoginHistorySchema.index({ country: 1 });
LoginHistorySchema.index({ success: 1 });
LoginHistorySchema.index({ riskScore: 1 });

export const LoginHistory = mongoose.model<ILoginHistory>('LoginHistory', LoginHistorySchema);