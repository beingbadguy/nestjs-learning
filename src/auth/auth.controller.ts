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
// import { AuthGuard } from '@nestjs/passport';
import { ChangePasswordDTO } from './dto/changePassword.dto';
import { AuthGuard } from 'src/guards/auth.guard';
import { Request } from '@nestjs/common';

interface AuthenticatedRequest extends Request {
  user: {
    userId: string;
    id: string;
    email: string;
  };
}

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

  //CHANGE PASSWORD
  @UseGuards(AuthGuard)
  @Post('change-password')
  async changePassword(
    @Req() req: AuthenticatedRequest,
    @Body() changePasswordDto: ChangePasswordDTO,
  ) {
    // console.log(req.user);
    const { userId } = req.user; // Assuming userId is attached to the request by AuthGuard
    return this.authService.resetPassword(
      changePasswordDto.oldPassword,
      changePasswordDto.newPassword,
      userId,
    );
  }

  //FORGET PASSWORD

  @Post('forget-password')
  async forgetPassword(@Body('email') email: string) {
    return this.authService.forgetPassword(email);
  }

  //RESET PASSWORD
  @Get('reset-password')
  async resetPassword(@Body('token') token: string, @Body('newPassword') newPassword: string) {
    return this.authService.resetPasswordWithToken(token, newPassword);
  }

}
