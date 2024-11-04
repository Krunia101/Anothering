import { Module } from '@nestjs/common';
import { TugasController } from './tugas.controller';
import { TugasService } from './tugas.service';

@Module({
  controllers: [TugasController],
  providers: [TugasService]
})
export class TugasModule {}
