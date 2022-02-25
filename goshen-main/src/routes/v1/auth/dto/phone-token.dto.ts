import {
  IsNotEmpty,
  MinLength,
  IsString,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export default class PhoneTokenDto {
    @ApiProperty({ type: String })
    @IsNotEmpty()
    @IsString()
    @MinLength(6)
    readonly token: string = '';

    @ApiProperty({ type: String })
    @IsNotEmpty()
    @IsString()
    @MinLength(6)
    readonly phone_number: string = '';
}
