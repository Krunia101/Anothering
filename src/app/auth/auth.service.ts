import { HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import BaseResponse from 'src/utils/response.utils';
import { User } from './auth.entity';
import { Repository } from 'typeorm';
import { ResponseSuccess } from 'src/Interpace';
import { LoginDto, RegisterDto, UserDto } from './auth.dto';
import { compare, hash } from 'bcrypt'; //import hash
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { access } from 'fs';
import { ResetPassword } from '../mail/reset_password.entity';
import { MailService } from '../mail/mail.service';
import { randomBytes } from 'crypto';
import { ResetPasswordDto } from '../mail/auth_reset.dto';

@Injectable()
export class AuthService extends BaseResponse {
  constructor(
    @InjectRepository(User) private readonly authRepository: Repository<User>,
    @InjectRepository(ResetPassword) private readonly resetPasswordRepository: Repository<ResetPassword>,
    private jwtService: JwtService, // panggil kelas jwt service
    private mailService: MailService
  ) {
    super();
  }

  generateJWT(payload: jwtPayload, expiresIn: string | number, token: any) {
    return this.jwtService.sign(payload, {
      secret: token,
      expiresIn: expiresIn,
    });
  } //membuat method untuk generate jwt

  async register(payload: RegisterDto): Promise<ResponseSuccess> {
    const checkUserExists = await this.authRepository.findOne({
      where: {
        email: payload.email,
      },
    });
    if (checkUserExists) {
      throw new HttpException('User already registered', HttpStatus.FOUND);
    }

    payload.password = await hash(payload.password, 12); //hash password
    await this.authRepository.save(payload);

    return this._success('Register Berhasil');
  }
  async login(payload: LoginDto): Promise<ResponseSuccess> {
    const checkUserExists = await this.authRepository.findOne({
      where: {
        email: payload.email,
      },
      select: {
        id: true,
        nama: true,
        email: true,
        password: true,
        refresh_token: true,
      },
    });

    if (!checkUserExists) {
      throw new HttpException(
        'User tidak ditemukan',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    const checkPassword = await compare(
      payload.password,
      checkUserExists.password,
    ); // compare password yang dikirim dengan password yang ada di tabel

    if (checkPassword) {
      const jwtPayload: jwtPayload = {
        id: checkUserExists.id,
        nama: checkUserExists.nama,
        email: checkUserExists.email,
        role: checkUserExists.role,
      };

      const accessToken = await this.generateJWT(
        jwtPayload,
        30,
        process.env.ACCESS_TOKEN_SECRET,
      );

      const refresh_token = await this.generateJWT(
        jwtPayload,
        '1d',
        process.env.REFRESH_TOKEN_SECRET,
      );

        await this.authRepository.update(
          { id: checkUserExists.id },
          { refresh_token: refresh_token },
        )

      return this._success('Login Success', {...checkUserExists, accessToken,refresh_token   });
    } else {
      throw new HttpException(
        'email dan password tidak sama',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
  }
  //Refresh Token
  async refreshToken(id: number, token: string): Promise<ResponseSuccess> {
    const checkUserExists = await this.authRepository.findOne({
      where: {
        id: id,
        refresh_token: token,
      },
      select: {
        id: true,
        nama: true,
        email: true,
        password: true,
        refresh_token: true,
      },
    });

    console.log('user', checkUserExists);
    if (checkUserExists === null) {
      throw new UnauthorizedException();
    }

    const jwtPayload: jwtPayload = {
      id: checkUserExists.id,
      role: checkUserExists.role,
      nama: checkUserExists.nama,
      email: checkUserExists.email,
    };

    const accessToken = await this.generateJWT(
      jwtPayload,
      30,
      process.env.ACCESS_TOKEN_SECRET,
    );

    const refresh_token = await this.generateJWT(
      jwtPayload,
      '1d',
      process.env.REFRESH_TOKEN_SECRET,
    );

    await this.authRepository.save({
      refresh_token: refresh_token,
      id: checkUserExists.id,
    });

    return this._success('Success', {
      ...checkUserExists,
      access_token: accessToken,
      refresh_token: refresh_token,
    });
  }
  //forgotPassword
  async forgotPassword(email: string): Promise<ResponseSuccess> {
    const user = await this.authRepository.findOne({
      where: {
        email: email,
      },
    });

    if (!user) {
      throw new HttpException(
        'Email tidak ditemukan',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
    const token = randomBytes(32).toString('hex'); // membuat token
    const link = `${process.env.BASE_CLIENT_URL}/auth/lupa-password/${user.id}/${token}`; //membuat link untuk reset password
    // await this.mailService.sendForgotPassword({
    //   email: email,
    //   name: user.nama,
    //   link: link,
    // });
    console.log(link);

    const payload = {
      user: {
        id: user.id,
      },
      token: token,
    };

    await this.resetPasswordRepository.save(payload); // menyimpan token dan id ke tabel reset password

    return this._success('Silahkan Cek Email');
  }
//reset password  

async resetPassword(
  user_id: number,
  token: string,
  payload: ResetPasswordDto,
): Promise<ResponseSuccess> {
  const userToken = await this.resetPasswordRepository.findOne({
    where: {
      token: token,
      user: {
        id: user_id,
      },
    },
  });

  if (!userToken) {
    throw new HttpException(
      'Token tidak valid',
      HttpStatus.UNPROCESSABLE_ENTITY,
    );
  }

  const now = new Date();
  const createdAt = userToken.created_at;
  const diff = (now.getTime() - createdAt.getTime()) / 1000; // dalam detik
  if (diff > 20) { // 1 menit
    throw new HttpException(
      'Kode verifikasi telah kadaluarsa',
      HttpStatus.UNPROCESSABLE_ENTITY,
    );
  }

  // kode verifikasi masih berlaku, lanjutkan proses reset password
  payload.new_password = await hash(payload.new_password, 12);
  await this.authRepository.save({
    password: payload.new_password,
    id: user_id,
  });
  await this.resetPasswordRepository.delete({
    user: {
      id: user_id,
    },
  });

  return this._success('Reset Passwod Berhasil, Silahkan login ulang');
}
}
