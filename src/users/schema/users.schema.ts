import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type UserDocument = User & Document;

@Schema({ timestamps: true, versionKey: false })
export class User {
  @Prop({ required: true, trim: true, maxlength: 50 })
  username: string;

  @Prop({
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    maxlength: 100,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  })
  email: string;

  @Prop({ required: true, minLength: 6 })
  password: string;

  @Prop({
    default: 'user',
    enum: ['user', 'admin', 'superadmin'],
  })
  role: string;
}
export const UserSchema = SchemaFactory.createForClass(User);
