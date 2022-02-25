/* eslint-disable camelcase */
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

import { RolesEnum } from '@decorators/roles.decorator';

@Schema()
export class User {
  @Prop({
    required: true,
    type: String,
  })
  name = '';

  @Prop({
    required: true,
    unique: true,
    type: String,
  })
  username = '';

  @Prop({
    type: String,
    index: {
      unique: true,
      partialFilterExpression: { phone_number: { $type: 'string' } },
    },
  })
  phone_number = '';

  @Prop({
    required: true,
    unique: true,
    type: String,
  })
  email = '';

  @Prop({
    required: true,
    type: String,
  })
  password = '';

  @Prop({
    required: false,
    type: String,
  })
  token = '';

  @Prop({
    required: false,
    type: String,
  })
  resetToken = ''

  @Prop({
    required: false,
    type: Boolean,
  })
  phone_validated = false;

  @Prop({
    required: true,
    type: Boolean,
  })
  verified = false;

  @Prop({
    required: false,
    type: String,
  })
  country_id = '';

  @Prop({
    type: RolesEnum,
    required: false,
    default: RolesEnum.user,
  })
  role: RolesEnum = RolesEnum.user;
}
export type UserDocument = User & Document;

export const UserSchema = SchemaFactory.createForClass(User).set('versionKey', false);
