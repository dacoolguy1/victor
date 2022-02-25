import {
  IsNotEmpty,
  IsString,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
export default class AddCountryDto {
    @ApiProperty({ type: String, description: 'Country Name', name: 'country' })
    @IsNotEmpty()
    @IsString()
    readonly country: string = '';

    @ApiProperty({ type: String, description: 'Country Telephone Code', name: 'country_code' })
    @IsNotEmpty()
    @IsString()
    readonly calling_code: string = '';
}
