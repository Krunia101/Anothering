import { BaseEntity, Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Book extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  title:string

  @Column()
  author : string

  @Column({type: 'text'})
  description : string

  @Column({
    type: 'datetime', default: () => 'CURRENT_TIMESTAMP',})
  created_at: Date;
  @Column({
    type: 'datetime', default: () => 'CURRENT_TIMESTAMP',})
  updated_at: Date;
}
