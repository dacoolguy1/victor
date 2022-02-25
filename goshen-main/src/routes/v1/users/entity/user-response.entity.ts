/* eslint-disable max-classes-per-file */
/* eslint-disable camelcase */
import { Exclude, Type, Transform } from 'class-transformer';
import { ValidateNested } from 'class-validator';
import { ObjectId } from 'mongodb';
import { PaginationParamsInterface } from '@interfaces/pagination-params.interface';
import { RolesEnum } from '@decorators/roles.decorator';

class Data {
  @Transform(({ value }) => value.toString(), { toPlainOnly: true })
  _id: ObjectId = new ObjectId();

  role: RolesEnum = RolesEnum.user;

  verified: boolean = false;

  name: string = '';

  email: string = '';

  username: string = '';

  phone_number: string = '';

  @Exclude()
  password: string = '';
}

export default class UserResponseEntity {
  @ValidateNested({ each: true })
  @Type(() => Data)
  data?: [{
    _id: ObjectId;

    role: string;

    verified: false;

    name: string;
    email: string;
    username: string;
    phone_number: string;

    password: string;
  }] = [{
    _id: new ObjectId(),

    role: '',

    verified: false,

    email: '',

    name: '',

    username: '',

    phone_number: '',

    password: '',
  }]

  collectionName?: string = '';

  options?: {
    location: string,
    paginationParams: PaginationParamsInterface,
    totalCount: number,
  }
}
