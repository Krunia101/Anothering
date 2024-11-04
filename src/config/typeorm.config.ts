import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { User } from 'src/app/auth/auth.entity';
import { ResetPassword } from 'src/app/mail/reset_password.entity';
import { Book } from 'src/book/book.entity';
import { Siswa } from 'src/ujian/ujian.entity';

export const typeOrm: TypeOrmModuleOptions = {
  type: 'mysql',
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT), 
  username: process.env.DB_USERNAME, 
  password: process.env.DB_PASSWORD, 
  database: process.env.DB_DATABASE,
  entities: [Siswa, Book, User, User, ResetPassword],
  synchronize: true,
  logging: true,
};