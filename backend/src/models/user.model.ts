import mongoose, { Schema, Document, Model } from "mongoose";
import bcrypt from "bcryptjs";

// Interface for credential objects
export interface ICredential {
  id: string;
  publicKey: string;
  counter: number;
}

// Interface for last login tracking
export interface ILastLogin {
  ip?: string;
  country?: string;
  region?: string;
  city?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isVPN?: boolean;
  isProxy?: boolean;
  timestamp?: Date;
}

// Main User interface
export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  phone?: string;
  role: "user" | "admin";
  mfaEnabled: boolean;
  mfaSecret?: string;
  totpSecret?: string;
  credentials: ICredential[];
  lastLogin?: ILastLogin;
  loginAttempts?: number;
  lockUntil?: Date;
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const UserSchema: Schema<IUser> = new Schema(
  {
    username: { 
      type: String, 
      required: true, 
      unique: true, 
      trim: true 
    },
    email: { 
      type: String, 
      required: true, 
      unique: true, 
      lowercase: true, 
      trim: true 
    },
    phone: { 
      type: String, 
      required: false 
    },
    password: { 
      type: String, 
      required: true 
    },
    role: { 
      type: String, 
      enum: ["user", "admin"], 
      default: "user" 
    },
    mfaEnabled: { 
      type: Boolean, 
      default: false 
    },
    mfaSecret: { 
      type: String 
    },
    totpSecret: { 
      type: String 
    },
    credentials: [
      {
        id: { type: String, required: true },
        publicKey: { type: String, required: true },
        counter: { type: Number, required: true },
      },
    ],
    lastLogin: {
      ip: { type: String },
      country: { type: String },
      region: { type: String },
      city: { type: String },
      lat: { type: Number },
      lon: { type: Number },
      timezone: { type: String },
      isVPN: { type: Boolean },
      isProxy: { type: Boolean },
      timestamp: { type: Date }
    },
    loginAttempts: { 
      type: Number, 
      default: 0 
    },
    lockUntil: { 
      type: Date 
    }
  },
  { 
    timestamps: true 
  }
);

// Hash password before saving
UserSchema.pre<IUser>("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare passwords
UserSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

const User: Model<IUser> = mongoose.model<IUser>("User", UserSchema);
export default User;