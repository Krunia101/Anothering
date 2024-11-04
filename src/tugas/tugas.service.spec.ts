import { Test, TestingModule } from '@nestjs/testing';
import { TugasService } from './tugas.service';

describe('TugasService', () => {
  let service: TugasService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TugasService],
    }).compile();

    service = module.get<TugasService>(TugasService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
