/* eslint-disable camelcase */
import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength, MaxLength } from 'class-validator';

export default class CreateWalletDto {
    @ApiProperty({ type: String, description: 'Blockchain Name', name: 'blockchain' })
    @IsString()
    @MinLength(3)
    @MaxLength(10)
    readonly blockchain: string = '';
}
