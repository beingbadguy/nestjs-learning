import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document, mongo } from 'mongoose';

export type RefreshTokenDocument = Document & RefreshToken;

@Schema({
  timestamps: true,
  versionKey: false,
})
export class RefreshToken {
  @Prop({
    required: true,
    trim: true,
    unique: true,
    type: mongoose.Schema.Types.ObjectId,
  })
  userId: mongoose.Schema.Types.ObjectId;

  @Prop({
    required: true,
    trim: true,
    unique: true,
  })
  refreshToken: string;

  @Prop({
    required: true,
  })
  expiresAt: Date;
}

export const RefreshTokenSchema = SchemaFactory.createForClass(RefreshToken);
