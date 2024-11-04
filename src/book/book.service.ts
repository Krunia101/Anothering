import {
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Book } from './book.entity';
import { Any, Between, Like, Repository } from 'typeorm';
import { AnyTxtRecord, promises } from 'dns';
import { ResponsePagination, ResponseSuccess } from 'src/Interpace';
import { find, take } from 'rxjs';
import BaseResponse from 'src/utils/response.utils';
import { CreateBookDTO, UpdateBookDTO } from './book.dto';
import { FindBookDto } from './book.dto';

@Injectable()
export class BookService extends BaseResponse {
  constructor(
    @InjectRepository(Book) private readonly bookrepository: Repository<Book>,
  ) {
    super();
  }
  // Jadiin API
  // async fidAllBook(): Promise<ResponseSuccess> {
  //   const result = await this.bookrepository.find();
  // return { status: 'Succes', message: 'List buku di temukan', data: result };
  // }
  async fidAllBook(query: FindBookDto): Promise<ResponsePagination> {
    console.log('query', query);

    const {
      page,
      pageSize,
      limit,
      title,
      author,
      description,
      keyword,
      to_year,
      from_year,
    } = query;

    const filter: {
      [key: string]: any;
    } = {};

    const Search: {
       [key: string]: any 
      }[] = [];

    if (keyword){
      Search.push(
        {title: Like(`%${keyword}%`)},
        {author: Like(`%${keyword}%`)},
        {description: Like(`%${keyword}%`)},
        )

    }else {
      if (title) {
        filter.title = Like(`%${title}%`);
      }
      if (author) {
        filter.author = Like(`%${author}%`);
      }
      if (description) {
        filter.description = Like(`%${description}%`);
      }
      if (from_year && to_year) {
        filter.year = Between(from_year, to_year);
      }
  
    } 

    console.log(filter);
    console.log(keyword);
    console.log(page, pageSize);

    // const page = query.page;
    // const pagesize = query.pagesize;

    const result = await this.bookrepository.find({
      //skip: (Number(page) - 1) * Number(pagesize),
      where: keyword ? Search : filter,
      skip: limit,
      take: Number(pageSize),
    });

    const total = await this.bookrepository.count({
      where: filter,
    });

    return this._pagination(
      'List buku di temukan',
      result,
      total,
      page,
      pageSize,
    );
  }
  async findOne(id: number): Promise<ResponseSuccess> {
    const result = await this.bookrepository.findOne({ where: { id: id } });
    return { status: 'Succes', message: 'List buku di temukan', data: result };
  }
  //Nambah Buku

  async add(payload: CreateBookDTO): Promise<ResponseSuccess> {
    try {
      const save = await this.bookrepository.save(payload);

      return {
        status: 'Succes',
        message: 'Buku Berhasil ditambah',
        data: payload,
      };
    } catch (err) {
      throw new HttpException('Something went wrong', HttpStatus.BAD_REQUEST);
    } finally {
      console.log('final');
    }
  }

  //Detail Buku
  async detailBook(id: number): Promise<ResponseSuccess> {
    const result = await this.bookrepository.findOne({ where: { id: id } });

    if (result === null) {
      throw new NotFoundException('Book not found, pls try again');
    }
    return {
      status: 'Succes',
      message: 'Book Success to be added',
      data: result,
    };
  }

  //Update Buku
  async update(id: number, payload: UpdateBookDTO): Promise<ResponseSuccess> {
    try {
      const result = await this.bookrepository.update(id, {
        title: payload.title,
        author: payload.author,
        description: payload.description,
      });
      // const result = await this.bookrepository.update({id:id},{
      //   title: payload.title,
      //   author: payload.author,
      //   description: payload.description,
      // });

      return {
        status: 'Success',
        message: 'Book updated successfully',
        data: result,
      };
    } catch (err) {
      throw new HttpException('Something went wrong', HttpStatus.BAD_REQUEST);
    } finally {
      console.log('Done');
    }
  }

  //hapus buku
  async delete(id: number): Promise<ResponseSuccess> {
    const result = await this.bookrepository.delete(id);
    return {
      status: 'Success',
      message: 'Book deleted successfully',
      data: result,
    };
  }
  //banyak hapus
  async deleteAll(array: string[]): Promise<ResponseSuccess> {
    const deleted = await this.bookrepository.delete(array);
    if (deleted.affected === 0) {
      throw new HttpException('Book not found', HttpStatus.NOT_FOUND);
    }
    return {
      status: 'Success',
      message: 'Book deleted successfully',
      data: deleted,
    };
  }
}
