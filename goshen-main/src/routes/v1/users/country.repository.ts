/* eslint-disable camelcase */
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { Injectable } from '@nestjs/common';

import { CountryDocument, Country } from '@v1/users/schemas/countries.schema';
import AddCountryDto from '../auth/dto/add-country.dto';

@Injectable()
export default class CountryRepository {
  constructor(@InjectModel(Country.name) private countryModel: Model<CountryDocument>) {}

  public async create(country: AddCountryDto): Promise<Country> {
    const newCountry = await this.countryModel.create(country);

    return newCountry.toObject();
  }

  public async getAllCountry(): Promise<any> {
    const [countries] = await Promise.all([
      this.countryModel.find({}).lean(),
    ]);

    return { countries };
  }

  public getCountryCodeById(id: any): string {
    const { calling_code } = this.countryModel.findOne({ country: id }).lean() as unknown as Country;
    return calling_code;
  }
}
