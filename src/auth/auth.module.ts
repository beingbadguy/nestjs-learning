import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from 'src/users/users.module';
import { JwtService } from '@nestjs/jwt';

@Module({
  imports: [MongooseModule, UsersModule],
  providers: [AuthService, JwtService],
})
export class AuthModule {}
