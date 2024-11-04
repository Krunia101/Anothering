import { Module } from '@nestjs/common';
import { SiswaController } from './ujian.controller';
import { SiswaService } from './ujian.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Siswa } from './ujian.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Siswa])],
  controllers: [SiswaController],
  providers: [SiswaService],
})
export class SiswaModule {}