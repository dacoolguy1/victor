import { Module } from '@nestjs/common';
import { Routes, RouterModule } from 'nest-router';
import AuthModule from './auth/auth.module';
import UsersModule from './users/users.module';
import WalletModule from './wallets/wallet.module';

const routes: Routes = [
  {
    path: '/v1',
    children: [
      { path: '/auth', module: AuthModule },
      { path: '/users', module: UsersModule },
      { path: '/wallet', module: WalletModule },
    ],
  },
];

@Module({
  imports: [
    RouterModule.forRoutes(routes),
    AuthModule,
    UsersModule,
    WalletModule,
  ],
})
export default class V1Module {}
