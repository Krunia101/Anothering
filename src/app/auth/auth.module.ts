import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { TypeOrmModule } from "@nestjs/typeorm";
import { User } from "./auth.entity";
import { JwtModule } from "@nestjs/jwt";
import { JwtAccessTokenStrategy } from "./jwtAccessToken.strategy";
import { ResetPassword } from "../mail/reset_password.entity";
import { MailModule } from "../mail/mail.module";

@Module({
  imports:[TypeOrmModule.forFeature([User, ResetPassword  ]),
  JwtModule.register({ }),
  MailModule
],
  controllers: [AuthController],
  providers: [AuthService,JwtAccessTokenStrategy],
})
export class AuthModule {}