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

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private readonly refreshTokenModel: Model<RefreshToken>,
    private readonly jwtService: JwtService,
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
}
