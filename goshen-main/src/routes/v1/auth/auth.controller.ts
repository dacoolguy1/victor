/* eslint-disable camelcase */
import {
  Body,
  Controller,
  HttpCode,
  Get,
  Post,
  Delete,
  Param,
  Request,
  UnauthorizedException,
  UseGuards,
  NotFoundException,
  ForbiddenException,
  HttpStatus,
  Redirect,
  UseInterceptors,
  BadRequestException,
  UnprocessableEntityException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiBody,
  ApiOkResponse,
  ApiInternalServerErrorResponse,
  ApiUnauthorizedResponse,
  ApiBearerAuth,
  ApiNotFoundResponse,
  ApiBadRequestResponse,
  ApiConflictResponse,
  ApiNoContentResponse,
  ApiExtraModels,
  getSchemaPath,
} from '@nestjs/swagger';
import { JwtService } from '@nestjs/jwt';
import { Request as ExpressRequest } from 'express';
import { MailerService } from '@nestjs-modules/mailer';

import UsersService from '@v1/users/users.service';
import JwtAccessGuard from '@guards/jwt-access.guard';
import RolesGuard from '@guards/roles.guard';
import { User } from '@v1/users/schemas/users.schema';
import WrapResponseInterceptor from '@interceptors/wrap-response.interceptor';
import AuthBearer from '@decorators/auth-bearer.decorator';
import { Roles, RolesEnum } from '@decorators/roles.decorator';
import authConstants from '@v1/auth/auth-constants';
import { SuccessResponseInterface } from '@interfaces/success-response.interface';
import UsersEntity from '@v1/users/entity/user.entity';
import CountryService from '@v1/users/country.service';
import { DecodedUser } from './interfaces/decoded-user.interface';
import AuthService from './auth.service';
import RefreshTokenDto from './dto/refresh-token.dto';
import SignInDto from './dto/sign-in.dto';
import SignUpDto from './dto/sign-up.dto';
import JwtTokensDto from './dto/jwt-tokens.dto';
import ResponseUtils from '../../../utils/response.utils';
import AddPhoneDto from './dto/add-phone.dto';
import PhoneTokenDto from './dto/phone-token.dto';
import AddCountryDto from './dto/add-country.dto';
import ForgotPassword from './dto/forgot-password.dto';
import ResetPasswordDto from './dto/reset-password.dto';
import ChangePasswordDto from './dto/change-password.dto';

@ApiTags('Auth')
@UseInterceptors(WrapResponseInterceptor)
@ApiExtraModels(JwtTokensDto)
@Controller()
export default class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService,
    private readonly usersService: UsersService,
    private readonly mailerService: MailerService,
    private readonly countryService: CountryService,
  ) {}

  @ApiBody({ type: SignInDto })
  @ApiOkResponse({
    schema: {
      type: 'object',
      properties: {
        data: {
          $ref: getSchemaPath(JwtTokensDto),
        },
      },
    },
    description: 'Returns jwt tokens',
  })
  @ApiBadRequestResponse({
    schema: {
      type: 'object',
      example: {
        message: [
          {
            target: {
              email: 'string',
              password: 'string',
            },
            value: 'string',
            property: 'string',
            children: [],
            constraints: {},
          },
        ],
        error: 'Bad Request',
      },
    },
    description: '400. ValidationException',
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        details: {},
      },
    },
    description: '500. InternalServerError',
  })
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  async signIn(@Request() req: ExpressRequest): Promise<any> {
    const { email, password } = req.body;
    const user = await this.authService.validateUser(email, password);
    if (user != null) {
      return ResponseUtils.success(
        'tokens',
        await this.authService.login(user),
      );
    }
    throw new BadRequestException('invalid user details, please details check and try again.');
  }

  @ApiBody({ type: SignUpDto })
  @ApiOkResponse({
    schema: {
      type: 'object',
      example: {
        data: {
          type: 'auths',
          attributes: {
            message: 'Success! please verify your email',
            data: {
              email: 'email@example.com',
              name: 'John Doe',
              phone_number: '2340000000000',
              username: 'john_doe_2',
            },
          },
        },
        success: 'Registration Done',
      },
    },
    description: '201, Success',
  })
  @ApiBadRequestResponse({
    schema: {
      type: 'object',
      example: {
        message: [
          {
            target: {
              email: 'string',
              password: 'string',
              phone_number: 'string',
              name: 'string',
            },
            value: 'string',
            property: 'string',
            children: [],
            constraints: {},
          },
        ],
        error: 'Bad Request',
      },
    },
    description: '400. ValidationException',
  })
  @ApiConflictResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
      },
    },
    description: '409. ConflictResponse',
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        details: {},
      },
    },
    description: '500. InternalServerError',
  })
  @HttpCode(HttpStatus.CREATED)
  @Post('sign-up')
  async signUp(@Body() user: SignUpDto): Promise<any> {
    const param: any = user;
    await this.authService.validateUserInput(param);
    const userName = await this.authService.generateRandomFrom(user.name);
    const {
      _id, email, name, phone_number, username,
    } = await this.usersService.create({ ...param, username: userName }) as unknown as UsersEntity;

    const token = this.authService.createVerifyToken(_id);

    await this.mailerService.sendMail({
      to: email,
      from: process.env.MAILER_FROM_EMAIL,
      subject: authConstants.mailer.verifyEmail.subject,
      template: `${process.cwd()}/src/templates/verify-password`,
      context: {
        token,
        email,
        host: process.env.SERVER_HOST,
      },
    });

    return ResponseUtils.success('auth', {
      message: 'Success! please verify your email',
      data: {
        email, name, phone_number, username,
      },
    });
  }

  @ApiOkResponse({
    schema: {
      type: 'object',
      properties: {
        data: {
          $ref: getSchemaPath(JwtTokensDto),
        },
      },
    },
    description: '200, returns new jwt tokens',
  })
  @ApiUnauthorizedResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
      },
    },
    description: '401. Token has been expired',
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        details: {},
      },
    },
    description: '500. InternalServerError ',
  })
  @ApiBearerAuth()
  @Post('refresh-token')
  async refreshToken(
    @Body() refreshTokenDto: RefreshTokenDto,
  ): Promise<SuccessResponseInterface | never> {
    const decodedUser = this.jwtService.decode(
      refreshTokenDto.refreshToken,
    ) as DecodedUser;

    if (!decodedUser) {
      throw new ForbiddenException('Incorrect token');
    }

    const oldRefreshToken:
      | string
      | null = await this.authService.getRefreshTokenByEmail(decodedUser.email);

    // if the old refresh token is not equal to request refresh token then this user is unauthorized
    if (!oldRefreshToken || oldRefreshToken !== refreshTokenDto.refreshToken) {
      throw new UnauthorizedException(
        'Authentication credentials were missing or incorrect',
      );
    }

    const payload = {
      _id: decodedUser._id,
      email: decodedUser.email,
      role: decodedUser.role,
    };

    return ResponseUtils.success(
      'tokens',
      await this.authService.login(payload),
    );
  }

  @ApiNoContentResponse({
    description: 'No content. 204',
  })
  @ApiNotFoundResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        error: 'Not Found',
      },
    },
    description: 'User was not found',
  })
  @HttpCode(HttpStatus.NO_CONTENT)
  @Get('verify/:token')
  @Redirect('http://localhost:51966/emailverified')
  async verifyUser(@Param('token') token: string): Promise<SuccessResponseInterface | never> {
    const { id } = await this.authService.verifyEmailVerToken(
      token,
      authConstants.jwt.secrets.accessToken,
    );
    const foundUser = await this.usersService.getUnverifiedUserById(id) as unknown as UsersEntity;

    if (!foundUser) {
      throw new NotFoundException('The user does not exist');
    }

    return ResponseUtils.success(
      'users',
      await this.usersService.update(foundUser._id, { verified: true }),
    );
  }

  @ApiNoContentResponse({
    description: 'no content',
  })
  @ApiUnauthorizedResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
      },
    },
    description: 'Token has been expired',
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        details: {},
      },
    },
    description: 'InternalServerError',
  })
  @ApiBearerAuth()
  @UseGuards(JwtAccessGuard)
  @Delete('logout/:token')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@Param('token') token: string): Promise<{} | never> {
    const decodedUser: DecodedUser | null = await this.authService.verifyToken(
      token,
      authConstants.jwt.secrets.accessToken,
    );

    if (!decodedUser) {
      throw new ForbiddenException('Incorrect token');
    }

    const deletedUsersCount = await this.authService.deleteTokenByEmail(
      decodedUser.email,
    );

    if (deletedUsersCount === 0) {
      throw new NotFoundException();
    }

    return {};
  }

  @ApiNoContentResponse({
    description: 'no content',
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        details: {},
      },
    },
    description: '500. InternalServerError',
  })
  @ApiBearerAuth()
  @Delete('logout-all')
  @UseGuards(RolesGuard)
  @Roles(RolesEnum.admin)
  @HttpCode(HttpStatus.NO_CONTENT)
  async logoutAll(): Promise<{}> {
    return this.authService.deleteAllTokens();
  }

  @ApiOkResponse({
    type: User,
    description: '200, returns a decoded user from access token',
  })
  @ApiUnauthorizedResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
      },
    },
    description: '403, says you Unauthorized',
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        details: {},
      },
    },
    description: '500. InternalServerError',
  })
  @ApiBearerAuth()
  @UseGuards(JwtAccessGuard)
  @Get('token')
  async getUserByAccessToken(
    @AuthBearer() token: string,
  ): Promise<SuccessResponseInterface | never> {
    const decodedUser: DecodedUser | null = await this.authService.verifyToken(
      token,
      authConstants.jwt.secrets.accessToken,
    );

    if (!decodedUser) {
      throw new ForbiddenException('Incorrect token');
    }

    const { exp, iat, ...user } = decodedUser;

    return ResponseUtils.success(
      'users',
      user,
    );
  }

  @ApiOkResponse({
    type: User,
    description: '200, returns a decoded user from access token',
  })
  @Get('countries')
  async countries(): Promise<SuccessResponseInterface | never> {
    return ResponseUtils.success(
      'country',
      await this.countryService.getAllCountry(),
    );
  }

  @ApiBody({ type: AddCountryDto })
  @ApiOkResponse({
    schema: {
      type: 'object',
      example: {
        data: {
          type: 'country',
          attributes: {
            message: 'New country',
            data: {
              name: 'DenCountry',
              country_code: '2340000000000',
            },
          },
        },
        success: 'Operation Done',
      },
    },
    description: '201, Success',
  })
  @ApiBadRequestResponse({
    schema: {
      type: 'object',
      example: {
        message: [
          {
            target: {
              name: 'string',
              country_code: 'string',
            },
            value: 'string',
            property: 'string',
            children: [],
            constraints: {},
          },
        ],
        error: 'Bad Request',
      },
    },
    description: '400. ValidationException',
  })
  @ApiConflictResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
      },
    },
    description: '409. ConflictResponse',
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        details: {},
      },
    },
    description: '500. InternalServerError',
  })
  @HttpCode(HttpStatus.CREATED)
  @Post('countries')
  async saveCountry(@Body() params: AddCountryDto): Promise<any> {
    const country = await this.countryService.create(params);
    return ResponseUtils.success(
      'country',
      country,
    );
  }

  @ApiBody({ type: AddPhoneDto })
  @ApiOkResponse({
    schema: {
      type: 'object',
      example: {
        data: {
          type: 'auths',
          attributes: {
            message: 'Success! please verify your Phone Number',
            data: {
              phone_number: '2340000000000',
            },
          },
        },
        success: 'Registration Done',
      },
    },
    description: '200, Success',
  })
  @ApiBadRequestResponse({
    schema: {
      type: 'object',
      example: {
        message: [
          {
            target: {
              email: 'string',
              phone_number: 'string',
              country_id: 'string',
            },
            value: 'string',
            property: 'string',
            children: [],
            constraints: {},
          },
        ],
        error: 'Bad Request',
      },
    },
    description: '400. ValidationException',
  })
  @ApiConflictResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
      },
    },
    description: '409. ConflictResponse',
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        details: {},
      },
    },
    description: '500. InternalServerError',
  })
  @HttpCode(HttpStatus.CREATED)
  @Post('add-phone-number')
  async addPhoneNumber(@Body() params: AddPhoneDto): Promise<any> {
    const checkPhone = await this.usersService.getUserByPhoneNumber(params.phone_number);
    if (checkPhone && checkPhone.email !== params.email) {
      throw new ForbiddenException('phone number exists');
    }
    const user = await this.usersService.getUserByEmail(params.email) as unknown as UsersEntity;
    if (!user) {
      throw new NotFoundException('The user does not exist');
    }
    await this.usersService.update(user._id, params);
    const token = this.usersService.createPhoneToken(user._id);
    await this.authService.sendToken(params.calling_code, token, params.phone_number);
    return ResponseUtils.success('auth', {
      message: 'Success! please verify your phone number',
    });
  }

  @ApiBody({ type: PhoneTokenDto })
  @ApiOkResponse({
    schema: {
      type: 'object',
      example: {
        data: {
          type: 'auths',
          attributes: {
            message: 'Success! Phone Number verified',
            data: {
              phone_number: '2340000000000',
            },
          },
        },
        success: 'Verification Done',
      },
    },
    description: '200, Success',
  })
  @ApiBadRequestResponse({
    schema: {
      type: 'object',
      example: {
        message: [
          {
            target: {
              email: 'string',
              phone_number: 'string',
              country_id: 'string',
            },
            value: 'string',
            property: 'string',
            children: [],
            constraints: {},
          },
        ],
        error: 'Bad Request',
      },
    },
    description: '400. ValidationException',
  })
  @ApiConflictResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
      },
    },
    description: '409. ConflictResponse',
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      example: {
        message: 'string',
        details: {},
      },
    },
    description: '500. InternalServerError',
  })
  @HttpCode(HttpStatus.CREATED)
  @Post('validate-phone-number')
  async validatePhone(@Body() params: PhoneTokenDto): Promise<any> {
    const res = await this.authService.validatePhoneNumber(params.token, params.phone_number);
    return ResponseUtils.success('auth', {
      message: res,
    });
  }

  @Post('/forgot-password')
  async forgotPassword(@Body() param: ForgotPassword): Promise<any> {
    const token = await this.authService.forgotPassword(param);
    const { email } = param;
    await this.mailerService.sendMail({
      to: email,
      from: process.env.MAILER_FROM_EMAIL,
      subject: authConstants.mailer.verifyEmail.subject,
      template: `${process.cwd()}/src/templates/change-password`,
      context: {
        token,
      },
    });
    return ResponseUtils.success('auth', {
      message: 'Reset password token sent.',
    });
  }

  @Post('/reset-password')
  async resetPassword(@Body() params: ResetPasswordDto): Promise<any> {
    if ((await this.authService.resetTokenIsValid(params.token, params.email))) {
      await this.authService.setNewPassword(params.newPassword, params.oldPassword, params.email);
      return ResponseUtils.success('auth', {
        message: 'Reset completed',
      });
    }
    throw new BadRequestException('invalid Token supplied');
  }

  @Post('/change-password')
  async changePassword(@Body() params: ChangePasswordDto, @AuthBearer() token: string): Promise<any> {
    const decodedUser: DecodedUser | null = await this.authService.verifyToken(
      token,
      authConstants.jwt.secrets.accessToken,
    );
    if (decodedUser != null) {
      await this.authService.changePassword(params.oldPassword, params.newPassword, decodedUser.email);
      return ResponseUtils.success('auth', {
        message: 'password changed',
      });
    }
    throw new BadRequestException('unauthorized user');
  }
}
