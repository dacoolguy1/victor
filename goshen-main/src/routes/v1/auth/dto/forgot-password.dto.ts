import {
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsString,
  IsEmail,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export default class ForgotPassword {
    @ApiProperty({ type: String, description: 'User Email Address', name: 'email' })
    @IsNotEmpty()
    @IsString()
    @IsEmail()
    @MinLength(3)
    @MaxLength(128)
    readonly email: string = '';
}
