import {
  Injectable,
  HttpException,
  HttpStatus,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Like, Repository } from 'typeorm';
import { Siswa } from './ujian.entity';
import BaseResponse from 'src/utils/response.utils';
import { CreateUjianDTO, FindSiswaDto, UpdateUjianDTO } from './ujian.dto';
import { ResponseUjian, ResponseSuccess2 } from 'src/Interface';
import { ResponsePagination } from 'src/Interpace';
import BaseResponse2 from 'src/utils/response2.utils';
import { filter } from 'rxjs';
@Injectable()
export class SiswaService extends BaseResponse2 {
  constructor(
    @InjectRepository(Siswa)
    private readonly siswaRepository: Repository<Siswa>,
  ) {
    super();
  }

  // Show
  async fidAllBook(query: FindSiswaDto) {
    const { page, limit, pageSize } = query;
    const filter: {
      [key: string]: any;
    } = {};

    console.log(pageSize);
    const [data] = await this.siswaRepository.find({
      skip: (page - 1) * limit,
      take: Number(pageSize),
    });
    const total = await this.siswaRepository.count({
      where: filter,
    });

    return {
      status: 'Success',
      message: 'OK',
      keyword: '',
      data: [
        {
          ...data,
        },
      ],
      pagination: {
        total: total,
        page: page,
        total_page: Math.ceil(total - 1),
        pageSize: pageSize,
        nextPage: Number(page) + 1,
        previousPage: Number(page) - 1,
      },
    };
  }

  //findlist1
  async findOne(id: number, query: FindSiswaDto){
    const result = await this.siswaRepository.findOne({ where: { id: id } });
    return {
      status: 'Success',
      message: 'OK',
      data: [result],
      pagination: {},
    };
  }
  // Detail siswa
  async detailBook(id: number): Promise<ResponseSuccess2> {
    const result = await this.siswaRepository.findOne({ where: { id: id } });

    if (result === null) {
      throw new NotFoundException(`Siswa dengan id ${id} tidak di temukan`);
    }
    return {
      status: 'Success',
      message: 'OK',
      data: result,
    };
  }

  // Create Siswa
  async add(payload: CreateUjianDTO) {
    const existingEmail = await this.siswaRepository.findOne({
      where: { email: payload.email },
    });

    if (existingEmail) {
      throw new HttpException(
        'Email sudah digunakan',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    const siswa = new Siswa();
    siswa.nama = payload.nama;
    siswa.email = payload.email;
    siswa.tempat_lahir = payload.tempat_lahir;
    siswa.tanggal_lahir = payload.tanggal_lahir;
    siswa.nisn = payload.nisn;
    siswa.nik = payload.nik;
    siswa.alamat = payload.alamat;

    await this.siswaRepository.save(siswa);
    return {
      status: 'Succes',
      message: 'OK',
      data: siswa,
    };
  }

  // Update
  async update(id: number, payload: UpdateUjianDTO): Promise<ResponseSuccess2> {
    const existingEmail = await this.siswaRepository.findOne({
      where: { email: payload.email },
    });
    if (existingEmail && existingEmail.id !== id) {
      throw new HttpException(
        'Email sudah digunakan oleh siswa lain',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
    const currentSiswa = await this.siswaRepository.findOne({
      where: { id: id },
    });
    if (currentSiswa.email !== payload.email) {
      throw new HttpException(
        'Email sudah digunakan siswa lain',
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
    const result = await this.siswaRepository.update(id, payload);
    if (result.affected === 0) {
      throw new NotFoundException(`Siswa dengan id ${id} tidak ditemukan`);
    }
    const updatedData = await this.siswaRepository.findOne({
      where: { id: id },
    });
    return {
      status: 'Success',
      message: 'Data Siswa Berhasil di ubah',
      data: updatedData,
    };
  }
}
