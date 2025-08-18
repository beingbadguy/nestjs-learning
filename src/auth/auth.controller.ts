// src/modules/auth/auth.controller.ts
import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Req,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import { refreshTokenDTO } from './dto/refreshtoken.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // SIGNUP
  @Post('signup')
  async signup(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData);
  }

  // LOGIN
  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(@Body() credentials: LoginDto) {
    return this.authService.login(credentials);
  }

  // REFRESH TOKEN

  @Post('refresh-token')
  async refreshToken(@Body() tokenDto: refreshTokenDTO) {
    return this.authService.refreshToken(tokenDto);
  }
}
