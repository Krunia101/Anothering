import { IsString, MinLength } from "class-validator";

export class ResetPasswordDto {
    @IsString()
    @MinLength(8)
    new_password: string;
  }