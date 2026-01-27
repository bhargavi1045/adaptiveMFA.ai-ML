import mongoose, { Schema, Document, Model } from "mongoose";
import bcrypt from "bcryptjs";

export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  phone?: string;            // added for SMS
  role: "user" | "admin";
  mfaEnabled: boolean;
  mfaSecret?: string;        // general MFA secret
  totpSecret?: string;       // TOTP secret
  createdAt: Date;
  updatedAt: Date;
  credentials: Array<{
    id: string;
    publicKey: string;
    counter: number;
  }>;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const UserSchema: Schema<IUser> = new Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, required: false },           
    password: { type: String, required: true },
    role: { type: String, enum: ["user", "admin"], default: "user" },
    mfaEnabled: { type: Boolean, default: false },
    mfaSecret: { type: String },
    totpSecret: { type: String },                      
    credentials: [
      {
        id: { type: String, required: true },
        publicKey: { type: String, required: true },
        counter: { type: Number, required: true },
      },
    ],
  },
  { timestamps: true }
);

UserSchema.pre<IUser>("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

const User: Model<IUser> = mongoose.model<IUser>("User", UserSchema);
export default User;
