/* eslint-disable camelcase */
import * as bcrypt from 'bcrypt';

import {
  Injectable, UnprocessableEntityException, NotFoundException, BadRequestException, InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Types } from 'mongoose';

import UsersRepository from '@v1/users/users.repository';
import { UserInterface } from '@v1/users/interfaces/user.interface';
import UsersEntity from '@v1/users/entity/user.entity';
import { UserDocument } from '@v1/users/schemas/users.schema';
import { DecodedUser } from './interfaces/decoded-user.interface';
// import JwtTokensDto from './dto/jwt-tokens.dto';
import { LoginPayload } from './interfaces/login-payload.interface';

import authConstants from './auth-constants';
import AuthRepository from './auth.repository';
import ForgotPassword from './dto/forgot-password.dto';
import UsersService from '../users/users.service';
import WalletService from '../wallets/wallet.service';

// Set your app credentials
const credentials = {
  apiKey: '6daa13f2716251813337dd1a1967799ac4c860e021c05e87652a7e7f001b0dbf',
  username: 'sandbox',
};
const AfricasTalking = require('africastalking')(credentials);
// Get the SMS service
const sms = AfricasTalking.SMS;
@Injectable()
export default class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly usersRepository: UsersRepository,
    private readonly userService: UsersService,
    private readonly authRepository: AuthRepository,
    private readonly walletService: WalletService,
  ) {}

  public async validateUser(
    email: string,
    password: string,
  ): Promise<null | UserInterface> {
    const user = await this.usersRepository.getVerifiedUserByEmail(email) as unknown as UsersEntity;

    if (!user) {
      throw new NotFoundException('The user does not exist');
    }
    if (user.phone_number === '') {
      throw new InternalServerErrorException('this user does not have a phone number');
    }
    if (!user.phone_validated) {
      throw new InternalServerErrorException('Please validate your phone number');
    }
    const passwordCompared = await bcrypt.compare(password, user.password);

    if (passwordCompared) {
      return {
        _id: user._id,
        email: user.email,
        role: user.role,
      };
    }
    return null;
  }

  public async login(data: LoginPayload): Promise<any> {
    const payload: LoginPayload = {
      _id: data._id,
      email: data.email,
      role: data.role,
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: authConstants.jwt.expirationTime.accessToken,
      secret: authConstants.jwt.secrets.accessToken,
    });
    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: authConstants.jwt.expirationTime.refreshToken,
      secret: authConstants.jwt.secrets.refreshToken,
    });

    await this.authRepository.addRefreshToken(
      payload.email as string,
      refreshToken,
    );
    const authUser = await this.usersRepository.getVerifiedUserByEmail(payload.email) as unknown as UsersEntity;
    const decodedUser: DecodedUser | null = await this.verifyToken(
      accessToken,
      authConstants.jwt.secrets.accessToken,
    );
    const wallet = (decodedUser != null) && await this.walletService.getUserWallets(decodedUser._id);
    return {
      accessToken,
      refreshToken,
      authUser,
      wallet,
    };
  }

  public getRefreshTokenByEmail(email: string): Promise<string | null> {
    return this.authRepository.getToken(email);
  }

  public deleteTokenByEmail(email: string): Promise<number> {
    return this.authRepository.removeToken(email);
  }

  public deleteAllTokens(): Promise<string> {
    return this.authRepository.removeAllTokens();
  }

  public createVerifyToken(id: Types.ObjectId): string {
    return this.jwtService.sign(
      { id },
      {
        expiresIn: authConstants.jwt.expirationTime.accessToken,
        secret: authConstants.jwt.secrets.accessToken,
      },
    );
  }

  public verifyEmailVerToken(token: string, secret: string) {
    return this.jwtService.verifyAsync(token, { secret });
  }

  public async verifyToken(
    token: string,
    secret: string,
  ): Promise<DecodedUser | null> {
    try {
      const user = (await this.jwtService.verifyAsync(token, {
        secret,
      })) as DecodedUser | null;

      return user;
    } catch (error) {
      return null;
    }
  }

  public getRandomArbitrary(min: number, max: number): any {
    return Math.ceil(Math.random() * (max - min) + min);
  }

  public async validateUserName(username: any): Promise<Boolean> {
    if (await this.userService.getUserByUserName(username) === null) {
      return true;
    }
    return false;
  }

  public async generateRandomFrom(word: string):Promise<any> {
    const username = `${word.split(' ')[0].toLowerCase()
    }_${
      word.split(' ')[1] === undefined ? '' : word.split(' ')[1].toLowerCase()
    }${this.getRandomArbitrary(0, 9)}`;
    if (await this.validateUserName(username)) {
      return username;
    }
    return this.generateRandomFrom(word);
  }

  // eslint-disable-next-line no-dupe-class-members
  public async validateUserInput(param:any): Promise<Boolean> {
    const existingUser = await this.userService.getUserByEmail(param.email);
    if (existingUser !== null) {
      throw new UnprocessableEntityException('User email exists already');
    }
    return true;
  }

  public async sendToken(_countryCode: string, _token: string, _phone: string): Promise<any> {
    const options = {
      to: [`+${parseInt(_countryCode, 10)}${_phone}`],
      message: `Your verification code ${_token}`,
      from: '21721',
    };
    const res = await sms.send(options);
    return { _token, _phone, res };
  }

  public async validatePhoneNumber(requestToken: string, phone_number: any): Promise<any> {
    const user = await this.usersRepository.getByPhoneNumber(phone_number);
    if (!user) {
      throw new NotFoundException('The user does not exist');
    }
    if (user.token === requestToken) {
      const { _id } = user as unknown as UsersEntity;
      return this.usersRepository.updateById(_id, { phone_validated: true, token: '' });
    }
    throw new NotFoundException('invalid token, check and try again');
  }

  public async forgotPassword(forgotPassword: ForgotPassword): Promise<any> {
    const user = await this.userService.getUserByEmail(forgotPassword.email) as UserDocument;
    if (!user) {
      throw new BadRequestException('Email not found');
    }
    if (!user.verified) {
      throw new BadRequestException('You have not verified your email');
    }
    return this.userService.createResetToken(user._id);
  }

  public async resetTokenIsValid(token: string, email: string): Promise<any> {
    const user = await this.userService.getUserByEmail(email) as UserDocument;
    if (user != null && user.resetToken === token) {
      return true;
    }
    throw new BadRequestException('Invalid token supplied');
  }

  public async setNewPassword(newPassword: string, oldPassword: string, email: string): Promise<any> {
    const user = await this.userService.getVerifiedUserByEmail(email) as unknown as UsersEntity;
    const passwordCompared = await bcrypt.compare(oldPassword, user.password);
    if (passwordCompared) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await this.userService.update(user._id, { password: hashedPassword });
      return true;
    }
    throw new BadRequestException('invalid old password');
  }

  public async changePassword(oldPassword: string, newPassword: string, uuid: any): Promise<any> {
    const user = await this.userService.getVerifiedUserByEmail(uuid) as unknown as UsersEntity;
    const passwordCompared = await bcrypt.compare(oldPassword, user.password);
    if (passwordCompared) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await this.userService.update(user._id, { password: hashedPassword });
      return true;
    }
    throw new BadRequestException('invalid old password');
  }
}
