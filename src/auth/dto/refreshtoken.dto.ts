import { IsDate, IsNotEmpty, IsString } from 'class-validator';

export class refreshTokenDTO {
  @IsNotEmpty()
  @IsString()
  refreshToken: string;
}
