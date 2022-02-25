import { Types } from 'mongoose';
import { ApiProperty } from '@nestjs/swagger';
import { RolesEnum } from '@decorators/roles.decorator';

export default class UsersEntity {
  @ApiProperty({ type: String })
  _id: Types.ObjectId = new Types.ObjectId();

  @ApiProperty({ type: 'enum', enum: RolesEnum })
  role: RolesEnum = RolesEnum.user;

  @ApiProperty({ type: Boolean })
  verified: boolean = false;

  @ApiProperty({ type: Boolean })
  phone_validated: boolean = false;

  @ApiProperty({ type: String })
  email: string = '';

  @ApiProperty({ type: String })
  phone_number: string = '';

  @ApiProperty({ type: String })
  name: string = '';

  @ApiProperty({ type: String })
  username: string = '';

  @ApiProperty({ type: String })
  password: string = '';
}
