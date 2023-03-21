import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constants';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signup(dto: CreateAuthDto) {
    const { email, password } = dto;

    const userExists = await this.prisma.user.findUnique({
      where: { email },
    });

    if (userExists) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    return { message: 'User created succefully' };
  }

  async signin(createAuthDto: CreateAuthDto) {
    const { email, password } = createAuthDto;
    const foundUser = await this.prisma.user.findUnique({
      where: { email },
    });
    if (!foundUser) {
      throw new BadRequestException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      foundUser.hashedPassword,
    );

    if (!isPasswordValid) {
      throw new BadRequestException('Invalid credentials');
    }
    //sign jwt and return to the user
    const token = await this.signToken({
      id: foundUser.id,
      email: foundUser.email,
    });

    return { token };
  }
  async signout(createAuthDto: CreateAuthDto) {
    return 'This action adds a new auth';
  }

  async hashPassword(password: string) {
    const hashedPassword = await bcrypt.hash(password, 10);
    return hashedPassword;
  }

  async signToken(payload: { id: number; email: string }) {
    const token = await this.jwtService.sign(payload, { secret: jwtSecret });
    return token;
  }
}
