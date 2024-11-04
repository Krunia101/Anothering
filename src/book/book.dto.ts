import { OmitType } from "@nestjs/mapped-types";
import { Type } from "class-transformer";
import { IsNotEmpty, Length, IsInt, Max, Min, MinLength, IsOptional } from "class-validator";

export class BookDTO{

    @IsOptional()
    id: number;

    @IsNotEmpty({ message: 'title must not be empty or 5 characters' })
    @Length(5)
    title: string;

    @IsNotEmpty()
    author: string;

    @IsInt({ message: 'year must be an integer or between 2020 and 2025' })
    @Min(2020)
    @Max(2025)
    year: number;

    @IsNotEmpty()
    @MinLength(5)
    description: string;
}
//yang di dalam array adalah yang di kecualikan       ⏑⏑⏑⏑⏑
export class CreateBookDTO extends OmitType(BookDTO, ['id']){}
export class UpdateBookDTO extends BookDTO{}

export class FindBookDto {
    @IsInt()
    @Type(() => Number)
    page = 1;

    @IsInt()
    @Type(() => Number)
    pageSize = 10;

    @IsOptional()
    @IsInt()
    limit:number

    @IsOptional()
    title : string

    @IsOptional()
    author : string

    @IsOptional()
    description : string

    @IsOptional()
    @IsInt()
    @Type(() => Number)
    from_year : number

    @IsOptional()
    @IsInt()
    @Type(() => Number)
    to_year : number

    @IsOptional()
    keyword: string
} 
