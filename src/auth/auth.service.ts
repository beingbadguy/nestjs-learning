// import { AuthService } from './auth.service';

import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/users/schema/users.schema';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from 'src/users/schema/refreshtoken.schema';
import { refreshTokenDTO } from './dto/refreshtoken.dto';
import { v4 as uuidv4 } from 'uuid';
import { EmailService } from 'src/email/email.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private readonly refreshTokenModel: Model<RefreshToken>,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
  ) {}

  //TODO: LOGIN
  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    if (!email || !password) {
      throw new BadRequestException('Email and password are required');
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('Invalid email, try again');
    }
    const userExists = await this.userModel.findOne({ email });
    if (!userExists) {
      throw new UnauthorizedException('Invalid credentials, Try again');
    }

    const isPasswordCorrect = await bcrypt.compare(
      password,
      userExists.password,
    );
    if (!isPasswordCorrect) {
      throw new UnauthorizedException('Invalid credentials, Try again');
    }
    // Here you would typically generate a JWT token and return it

    const { accessToken, refreshToken } = await this.generateToken(
      userExists._id.toString(),
    );

    const response = {
      _id: userExists._id,
      username: userExists.username,
      email: userExists.email,
      accessToken,
      refreshToken,
    };

    return {
      message: 'Login Successful',
      data: response,
      statusCode: 200,
      success: true,
    };
  }

  //TODO: SIGNUP

  async signup(signupData: SignupDto) {
    const { username, email, password } = signupData;

    if (!username || !email || !password) {
      throw new BadRequestException('All fields are required');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('Invalid email format');
    }
    if (password.length < 6) {
      throw new BadRequestException(
        'Password must be at least 6 characters long',
      );
    }

    const userExists = await this.userModel.findOne({ email });
    if (userExists) {
      throw new BadRequestException('User already exists with this email');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new this.userModel({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    const { refreshToken, accessToken } = await this.generateToken(
      newUser._id.toString(),
    );

    const response = {
      _id: newUser._id,
      username: newUser.username,
      email: newUser.email,
      accessToken,
      refreshToken,
    };

    return {
      message: 'User created successfully',
      data: response,
      statusCode: 201,
      success: true,
    };
  }

  //TODO: Generate Token

  async generateToken(userId: string) {
    const payload = { userId };
    const accessToken = this.jwtService.sign(payload);
    // Here you would typically also create a refresh token and save it to the database
    const refreshToken = uuidv4();

    // storing in db

    await this.storeRefreshToken(refreshToken, userId);

    return {
      accessToken,
      refreshToken,
    };
  }

  // TODO: REFRESH TOKEN
  async storeRefreshToken(refreshToken: string, userId: string) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 3);
    await this.refreshTokenModel.findOneAndUpdate(
      { userId },
      { refreshToken, expiresAt },
      { upsert: true, new: true },
    );
  }

  async refreshToken(refreshToken: refreshTokenDTO) {
    const existingToken = await this.refreshTokenModel.findOneAndDelete(
      {
        refreshToken: refreshToken.refreshToken,
        expiresAt: { $gt: new Date() },
      },
      {
        upsert: true,
      },
    );

    if (!existingToken) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    return this.generateToken(existingToken.userId.toString());
  }

  async resetPassword(
    oldPassword: string,
    newPassword: string,
    userId: string,
  ) {
    if (!oldPassword || !newPassword) {
      throw new BadRequestException('Enter password carefully');
    }

    // check newPassword length
    if (newPassword.length < 6) {
      throw new BadRequestException('Password length must be 6 or more');
    }

    if (!userId) {
      throw new UnauthorizedException('Invalid user, please login again');
    }

    if (oldPassword === newPassword) {
      throw new BadRequestException(
        'New password cannot be same as old password',
      );
    }
    const user = await this.userModel.findById(userId);
    console.log(user, ' : THIS IS THE USER');
    if (!user) {
      throw new BadRequestException('Invalid User, Please login again');
    }

    const isOldPasswordCorrect = await bcrypt.compare(
      oldPassword,
      user.password,
    );
    if (!isOldPasswordCorrect) {
      throw new BadRequestException('Please enter the correct old password');
    }

    const isNewPasswordSameAsOld = await bcrypt.compare(
      newPassword,
      user.password,
    );

    if (isNewPasswordSameAsOld) {
      throw new BadRequestException(
        'New password cannot be same as the old password!',
      );
    }

    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    if (user) {
      user!.password = newHashedPassword;
    }

    await user?.save();

    return {
      message: 'Password changed successfully!',
      data: user,
      success: true,
    };
  }

  async forgetPassword(email: string) {
    if (!email) {
      throw new BadRequestException('Email is required');
    }
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('User not found with this email');
    }
    const token = uuidv4(); // Generate a unique token for password reset

    user.resetToken = token;
    user.resetTokenExpiration = new Date(Date.now() + 3600000); // Token

    const resetLink = `http://yourapp.com/reset-password?token=${token}`;

    await this.emailService.sendMail(
      email,
      'Password Reset Request',
      `You requested a password reset. Click the link below to reset your password:\n${resetLink}`,
      `<p>You requested a password reset. Click the link below to reset your password:</p><a href="${resetLink}">Reset Password</a>`,
    );

    await user.save();

    // Here you would typically send a reset password email with a token
    // For simplicity, we will just return a success message
    return {
      message: 'Reset password email sent successfully',
      success: true,
    };
  }

  async resetPasswordWithToken(token: string, newPassword: string) {
    if (!token || !newPassword) {
      throw new BadRequestException('Token and new password are required');
    }

    const user = await this.userModel.findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: new Date() },
    });

    if (!user) {
      throw new BadRequestException('Invalid or expired token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = '';
    user.resetTokenExpiration = new Date();

    await user.save();

    return {
      message: 'Password reset successfully',
      success: true,
    };
  }
}
