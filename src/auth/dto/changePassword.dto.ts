import { IsEmpty, IsString } from 'class-validator';

export class ChangePasswordDTO {
  @IsString()
//   @IsEmpty()
  oldPassword: string;

  @IsString()
//   @IsEmpty()
  newPassword: string;
}
