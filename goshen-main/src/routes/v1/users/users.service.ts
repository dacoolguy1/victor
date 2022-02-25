import * as bcrypt from 'bcrypt';

import { Types } from 'mongoose';
import { Injectable } from '@nestjs/common';
import SignUpDto from '@v1/auth/dto/sign-up.dto';
import { PaginationParamsInterface } from '@interfaces/pagination-params.interface';
import { PaginatedUsersInterface } from '@interfaces/paginatedEntity.interface';

import { User } from '@v1/users/schemas/users.schema';
import UsersRepository from './users.repository';

@Injectable()
export default class UsersService {
  constructor(private readonly usersRepository: UsersRepository) {}

  public async create(user: SignUpDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(user.password, 10);

    return this.usersRepository.create({
      ...user,
      password: hashedPassword,
      phone_number: null,
    });
  }

  public getVerifiedUserByEmail(
    email: string,
  ): Promise<User | null> {
    return this.usersRepository.getVerifiedUserByEmail(email);
  }

  public getVerifiedUserById(id: Types.ObjectId): Promise<User | null> {
    return this.usersRepository.getVerifiedUserById(id);
  }

  public getUnverifiedUserByEmail(
    email: string,
  ): Promise<User | null> {
    return this.usersRepository.getUnverifiedUserByEmail(email);
  }

  public getUnverifiedUserById(id: Types.ObjectId): Promise<User | null> {
    return this.usersRepository.getUnverifiedUserById(id);
  }

  public update(
    id: Types.ObjectId,
    data: any,
  ): Promise<User | null> {
    return this.usersRepository.updateById(id, data);
  }

  public createPhoneToken(_id: Types.ObjectId): string {
    const token: string = (`${Math.random()}`).substring(2, 8);
    this.usersRepository.updateById(_id, { token });
    return token;
  }

  public createResetToken(_id: Types.ObjectId): string {
    const resetToken: string = (`${Math.random()}`).substring(2, 8);
    this.usersRepository.updateById(_id, { resetToken });
    return resetToken;
  }

  public async getAllVerifiedWithPagination(
    options: PaginationParamsInterface,
  ): Promise<PaginatedUsersInterface> {
    return this.usersRepository.getAllVerifiedWithPagination(options);
  }

  public getUserByEmail(email: string): Promise<User | null> {
    return this.usersRepository.getByEmail(email);
  }

  public getUserByPhoneNumber(phone: string): Promise<User | null> {
    return this.usersRepository.getByPhoneNumber(phone);
  }

  public getById(id: Types.ObjectId): Promise<User | null> {
    return this.usersRepository.getById(id);
  }

  public async getUserByUserName(username: string): Promise<User | null> {
    return this.usersRepository.getUserByUserName(username);
  }
}
