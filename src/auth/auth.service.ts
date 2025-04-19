import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { PrismaClient } from 'generated/prisma';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { CredentialsUser } from './dto/credentialUser.dto';
import { JwtService } from '@nestjs/jwt';
import { envs } from 'src/config/envs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');
  constructor(private readonly jwtService: JwtService) {
    super();
  }
  async onModuleInit() {
    await this.$connect();
  }
  async create(createAuthDto: CreateAuthDto) {
    const { email, password } = createAuthDto;
    const hashPassword = bcrypt.hashSync(password, 10);
    try {
      const user = await this.user.findUnique({
        where: { email, isActive: true },
      });
      if (user)
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Email exist, please login',
        });

      const newUser = await this.user.create({
        data: {
          ...createAuthDto,
          password: hashPassword,
        },
        omit: { password: true, isActive: true },
      });

      return {
        user: newUser,
        token: await this.createToken({ sub: newUser.id }),
      };
    } catch (error) {
      this.handleErrors(error);
    }
  }

  async findUser(credentialUser: CredentialsUser) {
    const { email, password } = credentialUser;
    try {
      const user = await this.user.findUnique({
        where: { email, isActive: true },
        omit: { isActive: true },
      });
      if (!user)
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: 'invalid credentials',
        });

      const isValidPassword = bcrypt.compareSync(password, user.password);
      if (!isValidPassword)
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: 'Invalid Credentials',
        });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: __, ...rest } = user;

      return {
        user: rest,
        token: await this.createToken({ sub: rest.id }),
      };
    } catch (error) {
      this.handleErrors(error);
    }
  }

  async verifyToken(token: string) {
    try {
      const payload = await this.jwtService.verifyAsync<{ sub: string }>(
        token,
        {
          secret: envs.jwt_secret,
        },
      );
      if (!payload)
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: 'Invalid Token',
        });

      return {
        user: {
          id: payload.sub,
        },
        token: await this.createToken({ sub: payload.sub }),
      };
    } catch (error) {
      this.handleErrors(error);
    }
  }

  private async createToken(payload: { sub: string }) {
    return await this.jwtService.signAsync(payload);
  }

  private handleErrors(error: any) {
    if (error instanceof RpcException) throw error;
    this.logger.log(error);
    throw new RpcException({
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'please check logs',
    });
  }
}
