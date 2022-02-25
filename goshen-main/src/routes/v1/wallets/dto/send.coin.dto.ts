/* eslint-disable camelcase */
import { ApiProperty } from '@nestjs/swagger';
import {
  IsNotEmpty, IsString, MinLength, MaxLength, IsNumber,
} from 'class-validator';

export default class sendCoinDto {
    @ApiProperty({ type: String, description: 'Address of Receiver', name: 'address' })
    @IsString()
    @IsNotEmpty()
    @MinLength(3)
    @MaxLength(42)
    readonly address: string = '';

    @ApiProperty({ type: Number, description: 'Amount to send', name: 'amount' })
    @IsNumber()
    @IsNotEmpty()
    readonly amount: string = '';

    @ApiProperty({ type: Number, description: 'Wallet Name', name: 'wallet_name' })
    @IsString()
    @IsNotEmpty()
    @MinLength(3)
    @MaxLength(42)
    readonly wallet_name: string = '';
}
