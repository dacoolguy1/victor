/* eslint-disable camelcase */
import {
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsString,
  IsEmail,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export default class AddPhoneDto {
    @ApiProperty({ type: String })
    @IsNotEmpty()
    @IsString()
    @MinLength(11)
    @MaxLength(15)
    readonly phone_number: string = '';

    @ApiProperty({ type: String, description: 'User Email Address', name: 'email' })
    @IsNotEmpty()
    @IsString()
    @IsEmail()
    @MinLength(3)
    @MaxLength(128)
    readonly email: string = '';

    @ApiProperty({ type: String, description: 'Country code', name: 'calling_code' })
    @IsNotEmpty()
    @IsString()
    readonly calling_code: string = '';
}
