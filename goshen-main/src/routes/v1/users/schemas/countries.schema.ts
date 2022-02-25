import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class Country {
    @Prop({
      required: true,
      type: String,
    })
    country = '';

    @Prop({
      required: true,
      type: String,
    })
    calling_code = '';
}
export type CountryDocument = Country & Document;
export const CountrySchema = SchemaFactory.createForClass(Country).set('versionKey', false);
