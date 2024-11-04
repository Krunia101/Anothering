import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity('siswa')
export class Siswa {
  map(arg0: (item: any) => { id: any; nama: any; }) {
    throw new Error('Method not implemented.');
  }
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  nama: string;

  @Column({ unique: true })
  email: string;

  @Column({type : 'text'})
  tempat_lahir: string;

  @Column()
  tanggal_lahir: Date;

  @Column()
  nisn: string;

  @Column()
  nik: string;

  @Column({type : 'text'})
  alamat: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  created_at: Date;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  updated_at: Date;
}