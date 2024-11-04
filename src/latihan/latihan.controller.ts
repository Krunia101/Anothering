import { Body, Controller, Get, Param, Post, Query } from '@nestjs/common';
import { LatihanService } from './latihan.service';
import { query } from 'express';

@Controller('latihan')
export class LatihanController {
  constructor(
    private readonly latihanService: LatihanService
  ) {}

  @Get()
  getHello(@Query() query: any) {
    return this.latihanService.findAll(query);
  }

  @Get()
  findAll(@Query() query: any) {
    return {
      method: 'GET',
      query: query
    };
  }

  @Get('detail/:id/:name')
  detail(@Param('id') id: string, @Param('name') name: string) {
    return this.latihanService.findDetail(id, name);
  }
  @Get('detail/:id/:name')
  detail2(@Param('id') id: string, @Param('name') name: string) {
    return {
      method: 'GET',
      msg: `Id player adalah ${id}`,
      msg2: `Nama player adalah ${name}`,
    };
  }

  @Post('simpan')
    register(@Body() payload:any) {
      return {
        method : 'GET',
        payload : payload
      }
  }

  @Post('update/:id')
    updater(@Param('id') id: string,@Body() payload:any) {
      return {
        method : 'GET',
        id_user: `${id}`,
        payload : payload
      }
  }

}