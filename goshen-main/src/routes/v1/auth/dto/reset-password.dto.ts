import {
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsString,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export default class ResetPasswordDto {
    @ApiProperty({ type: String, name: 'oldPassword' })
    @IsNotEmpty()
    @IsString()
    @MinLength(8)
    @MaxLength(64)
    readonly oldPassword: string = '';

    @ApiProperty({ type: String })
    @IsNotEmpty()
    @IsString()
    @MinLength(8)
    @MaxLength(64)
    readonly newPassword: string = '';

    @ApiProperty({ type: String })
    @IsNotEmpty()
    @IsString()
    readonly email: string = '';

    @ApiProperty({ type: String })
    @IsNotEmpty()
    @IsString()
    @MaxLength(6)
    readonly token: string = '';
}
