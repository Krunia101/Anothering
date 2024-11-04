import {  Controller,  Get,  Post,  Param,  Put,  Delete,  Body,  Query,} from '@nestjs/common';

@Controller('tugas')
export class TugasController {
  @Get('list')
  getlist(@Body() filter: any) {
    return {
      msg: 'succes',
      filter: filter,
    };
  }

  @Get('/:id/detail')
  getlist2(@Param('id') id: any) {
    return {
      status: 'succes',
      id: `Id player ${id} berhasil di temuka`,
    };
  }

  @Post('simpan')
  simpanan(@Body() payload: any) {
    return {
      status: 'succes',
      msg: 'berhasil disimpan',
      payload: payload,
    };
  }
  @Delete('/:id/delete')
  delete(@Param('id') id: any) {
    return {
      status: 'succes',
      msg : `id player ${id} di hapus`,
    };
  }
}
