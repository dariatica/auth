import { IsString } from 'class-validator';

export class CreateAuthDto {
  @IsString()
  email: string;
  @IsString()
  userName: string;
  @IsString()
  password: string;
}
