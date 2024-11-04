import { MESSAGES } from '@nestjs/core/constants';
import { OmitType } from '@nestjs/mapped-types';
import { Type } from 'class-transformer';
import {
  IsNotEmpty,
  IsInt,
  MinLength,
  IsOptional,
  IsEmail,
  IsDate,
} from 'class-validator';

export class UjianDTO {
  @IsOptional()
  id: number;

  @IsNotEmpty({ message: 'Nama tidak boleh kosong' })
  nama: string;

  @IsNotEmpty({
    message: 'Format email salah, harap masukkan email yang valid',
  })
  email: string;

  @IsNotEmpty({ message: 'Tempat lahir tidak boleh kosong' })
  tempat_lahir: string;

  @IsNotEmpty({message : 'Format Tanggal Lahir salah  '})
  @IsDate({message : 'Format Tanggal Lahir salah'})
  tanggal_lahir: Date;

  @IsNotEmpty()
  @MinLength(10, {message :'NISN harus terdiri dari 10 karakter' })
  nisn: string;

  @IsNotEmpty()
  @MinLength(16, {message :'NIK harus terdiri dari 16 karakter' })
  nik: string;

  @IsNotEmpty({message : 'Format Tanggal Lahir salah  '})
  alamat: string;

}

export class CreateUjianDTO extends OmitType(UjianDTO, ['id']) {}
export class UpdateUjianDTO extends UjianDTO {}

export class FindSiswaDto {
  @IsInt()
  @Type(() => Number)
  page

  @IsInt()
  @Type(() => Number)
  pageSize

  @IsOptional()
  @IsInt()
  limit: number;


  @IsOptional()
  nama: string;

  @IsOptional()
  @IsNotEmpty({ message: 'Email tidak boleh kosong' })
  @IsEmail()
  email: string;

  @IsOptional()
  tempat_lahir: string;

  @IsDate()
  @IsOptional()
  tanggal_lahir: Date;

  @IsOptional()
  nisn: string;

  @IsOptional()
  nik: string;

  @IsOptional()
  alamat: string;

  @IsOptional()
  keyword: string;
}