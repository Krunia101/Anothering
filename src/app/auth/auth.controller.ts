import { Controller, Post, Body, Req, Get, Param } from "@nestjs/common";
import { LoginDto, RegisterDto, UserDto } from "./auth.dto";
import { AuthService } from "./auth.service";
import { JwtGuard, JwtGuardRefreshToken } from "./auth.guard";
import { UseGuards } from "@nestjs/common";
import { ResetPasswordDto } from "../mail/auth_reset.dto";

@Controller("auth")
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post("register")
  async register(@Body() payload: RegisterDto) {
    return  this.authService.register(payload);
  }
  @UseGuards(JwtGuard )
  @Get('refresh-token')
  async refreshToken(@Req() req) {
    const token = req.headers.authorization.split(' ')[1];
    const id = req.headers.id;
    return this.authService.refreshToken(+id, token);  }

  @Post('login')
  async login(@Body() payload: LoginDto) {
    return this.authService.login(payload);
  }

  @Post('lupa-password')
  async forgotPassowrd(@Body('email') email: string) {
    console.log('email', email);
    return this.authService.forgotPassword(email)
  }
@Post('reset-password/:user_id/:token')  // url yang dibuat pada endpont harus sama dengan ketika kita membuat link pada service forgotPassword
async resetPassword(
  @Param('user_id') user_id: string,
  @Param('token') token: string,
  @Body() payload: ResetPasswordDto,
) {
  return this.authService.resetPassword(+user_id, token, payload);
}
}