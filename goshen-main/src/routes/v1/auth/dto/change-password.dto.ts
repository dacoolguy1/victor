import {
  IsNotEmpty,
  IsString,
} from 'class-validator';

import { ApiProperty } from '@nestjs/swagger';

export default class ChangePasswordDto {
    @ApiProperty({ type: String })
    @IsNotEmpty()
    @IsString()
    readonly newPassword: string = '';

    @ApiProperty({ type: String })
    @IsNotEmpty()
    @IsString()
    readonly oldPassword: string = '';
}
