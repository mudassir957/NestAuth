import { IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class UserDto {
  @IsNumber()
  @IsNotEmpty()
  id: number;

  @IsNotEmpty()
  @IsString()
  username: string;

  @IsNotEmpty()
  @IsString()
  password: string;

  @IsNotEmpty()
  @IsString()
  role: string;
}
