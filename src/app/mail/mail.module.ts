import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { join } from 'path';
import { Global } from '@nestjs/common/decorators/modules';

@Global()
@Module({
  imports: [
    MailerModule.forRoot({
      transport: {
        host: process.env.MAIL_HOST || 'mail.smkmadinatul.sch.id', //sesuaikan konfigurasi 
        port: Number(process.env.MAIL_PORT) || 465,
        connectionTimeout : 1000,
        secure:true,
        auth: {
          user: process.env.MAIL_HOST || 'mail.smkmadinatul.sch.id', //sesuaikan user
          pass: process.env.MAIL_PASS || 'SMKMQ2024', //sesuaikan password 
        },
      },
      defaults: {
        from: "latihan-kirim-email@smkmadinatulquran.sch.id>",
      },
      template: {
        dir: join(__dirname, 'templates'),  // template akan di ambil dari handlebar yang ada pada folder templates
        adapter: new HandlebarsAdapter(),
        options: {
          strict: true,
        },
      },
    }),
  ],
  providers: [MailService],
  exports: [MailService], // 👈 export  mailService agar bisa digunakan di luar module mail
})
export class MailModule {}