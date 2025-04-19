import { IsString } from 'class-validator';

export class CredentialsUser {
  @IsString()
  email: string;
  @IsString()
  password: string;
}
