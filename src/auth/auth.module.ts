import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from 'src/users/users.module';
import { JwtService } from '@nestjs/jwt';

import { EmailModule } from 'src/email/email.module';

@Module({
  imports: [MongooseModule, UsersModule, EmailModule],
  providers: [AuthService, JwtService],
})
export class AuthModule {}
