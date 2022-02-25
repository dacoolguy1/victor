import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';

import { Country, CountrySchema } from '@v1/users/schemas/countries.schema';
import { UserSchema, User } from './schemas/users.schema';

import UsersController from './users.controller';
import UsersService from './users.service';
import UsersRepository from './users.repository';
import CountryService from './country.service';
import CountryRepository from './country.repository';

@Module({
  imports: [
    MongooseModule.forFeature([{
      name: User.name,
      schema: UserSchema,
    }]),
    MongooseModule.forFeature([{
      name: Country.name,
      schema: CountrySchema,
    }]),
  ],
  controllers: [UsersController],
  providers: [UsersService, UsersRepository, CountryService, CountryRepository],
  exports: [UsersService, UsersRepository, CountryService, CountryRepository],
})
export default class UsersModule {}
