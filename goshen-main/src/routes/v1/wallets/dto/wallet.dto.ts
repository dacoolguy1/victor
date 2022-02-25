/* eslint-disable camelcase */
import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength, MaxLength } from 'class-validator';

export default class WalletDto {
    @ApiProperty({ type: String, description: 'Wallet hash', name: 'wallet_name' })
    @IsString()
    @MinLength(3)
    @MaxLength(512)
    readonly wallet_name: string = '';
}
