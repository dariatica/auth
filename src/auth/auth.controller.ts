import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { CredentialsUser } from './dto/credentialUser.dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern({ cmd: 'createAuth' })
  create(@Payload() createAuthDto: CreateAuthDto) {
    return this.authService.create(createAuthDto);
  }

  @MessagePattern({ cmd: 'getUser' })
  findUser(@Payload() credentialUser: CredentialsUser) {
    return this.authService.findUser(credentialUser);
  }

  @MessagePattern({ cmd: 'verifyToken' })
  verifyToken(@Payload() token: string) {
    return this.authService.verifyToken(token);
  }
}
