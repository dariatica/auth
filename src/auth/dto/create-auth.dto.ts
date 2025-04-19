import { IsString, IsStrongPassword } from 'class-validator';

export class CreateAuthDto {
  @IsString()
  email: string;
  @IsString()
  @IsStrongPassword()
  password: string;
  @IsString()
  name: string;
}
