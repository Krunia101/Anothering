import { Controller, Get, Post, Put, Delete, Patch } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post()
  create(): string {
    return "Ok!";
  }
  @Post("tes")
  create2(): string {
    return "Ok! tes";
  }
  @Get()
  getHello(): string {
    return "Belajar Routing NestJS";
  }

  @Get("list")
  getHello2(): string {
    return "Belajar Routing NestJS dengan NestJS.";
  }

  @Put()
  update(){
    return "Ini untuk update";
  }
  @Put("update")
  update2(){
    return "Ini untuk update-update";
  }

}
