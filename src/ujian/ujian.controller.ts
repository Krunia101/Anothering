import { Controller, Post, Get, Param, Put, Delete, Body } from '@nestjs/common';
import { SiswaService } from './ujian.service';
import { Siswa } from './ujian.entity';
import { CreateUjianDTO, FindSiswaDto, UpdateUjianDTO } from './ujian.dto';
import { Pagination } from 'src/utils/decorator/pagenation';

@Controller('siswa')
export class SiswaController {
  constructor(private readonly siswaService: SiswaService) {}

  @Get('list')
  async fidAllBook(@Pagination() query: FindSiswaDto) {
    return this.siswaService.fidAllBook(query);
  }
  @Get('list1')
  async findOne(@Pagination() query: FindSiswaDto) {
    return this.siswaService.findOne(2, query);
  }
  @Get('detail/:id')
  async detailBook(@Param('id') id: number) {
    return this.siswaService.detailBook(+id);
  }

  @Post('create')
  async createbook(@Body() payload:CreateUjianDTO){
    return this.siswaService.add(payload);
  }
  @Put('update/:id')
  async updateBook(@Param('id') id: number, @Body() payload: UpdateUjianDTO) {
    return this.siswaService.update(id, payload);
  }
}