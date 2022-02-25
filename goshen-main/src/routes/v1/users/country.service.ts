import { Injectable, NotFoundException } from '@nestjs/common';

import { Country } from '@v1/users/schemas/countries.schema';

import CountryRepository from './country.repository';
import AddCountryDto from '../auth/dto/add-country.dto';

@Injectable()
export default class CountryService {
  constructor(private readonly countryRepository: CountryRepository) {}

  public async create(country: AddCountryDto): Promise<Country> {
    return this.countryRepository.create(country);
  }

  public async getAllCountry(): Promise<any> {
    return this.countryRepository.getAllCountry();
  }

  public getCountryCode(id: any): string {
    const code = this.countryRepository.getCountryCodeById(id);
    console.log(code, id);
    if (!code) {
      throw new NotFoundException('The country does not exist');
    }
    return code;
  }
}
