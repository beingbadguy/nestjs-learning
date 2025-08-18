import { Logger, Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth/auth.controller';
import { AuthService } from './auth/auth.service';
import { AuthModule } from './auth/auth.module';
import mongoose from 'mongoose';
import { JwtModule, JwtService } from '@nestjs/jwt';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        global: true,
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '1h' }, // Adjust the expiration time as needed
      }),
      inject: [ConfigService],
    }),
    MongooseModule.forRootAsync({
      useFactory: (configService: ConfigService) => {
        const logger = new Logger('MongooseModule');
        const uri = configService.get<string>('MONGODB_URI');
        mongoose.connection.on('connected', () => {
          logger.log(`✅ Connected to MongoDB at ${uri}`);
        });
        mongoose.connection.on('error', (error) => {
          logger.error(`MongoDB connection error: ${error.message}`);
        });
        mongoose.connection.on('disconnected', () => {
          logger.warn(`Disconnected from MongoDB at ${uri}`);
        });

        return { uri };
      },
      inject: [ConfigService],
    }),
    UsersModule,
    AuthModule,
  ],
  controllers: [AppController, AuthController],
  providers: [AppService, AuthService],
  // exports: [JwtService],
})
export class AppModule {}
