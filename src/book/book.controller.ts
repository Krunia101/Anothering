import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Delete,
  Query,
  Req
} from '@nestjs/common';
import { BookService } from './book.service';
import { CreateBookDTO, FindBookDto, UpdateBookDTO } from './book.dto';
import { query } from 'express';
import { Pagination } from 'src/utils/decorator/pagenation';
import { UseGuards } from '@nestjs/common';
import { JwtGuard, JwtGuardRefreshToken } from 'src/app/auth/auth.guard';
import { AuthService } from 'src/app/auth/auth.service';
import { async } from 'rxjs';

@UseGuards(JwtGuard, JwtGuardRefreshToken)
@Controller('book')
export class BookController {
  constructor(private bookSevice: BookService) {}

  @Get('list')
  async fidAllBook(@Pagination() query: FindBookDto) {
    return this.bookSevice.fidAllBook(query);
  }
  @UseGuards(JwtGuard)
  @Get('list1')
  async findOne() {
    return this.bookSevice.findOne(2);
  }
  
  @Post('nambah')
  async createBook(@Body() payload: CreateBookDTO) {
    return this.bookSevice.add(payload);
  }

  @Get('detail/:id')
  async detailBook(@Param('id') id: number) {
    return this.bookSevice.detailBook(+id);
  }

  @Put('update/:id')
  async updateBook(@Param('id') id: number, @Body() payload: UpdateBookDTO) {
    return this.bookSevice.update(id, payload);
  }

  @Delete('delete/:id')
  async deleteBook(@Param('id') id: number) {
    return this.bookSevice.delete(id);
  }

  @Delete('delete')
  async deleteAllBook(@Query('id') id: string) {
    const idArray = id.split(',');
    return this.bookSevice.deleteAll(idArray);
  }
}