import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from './auth.guard';
import { Request } from '@nestjs/common';
import { Public } from './decorators/public.decorator';
import { UserDto } from 'src/users/dto/users.dto';
import { Roles } from './roles.decorator';
import { UsersService } from 'src/users/users.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UsersService,
  ) {}

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  signIn(@Body() userDto: UserDto) {
    if (!userDto.username || !userDto.password) {
      return 'Please enter username and password';
    }
    return this.authService.singIn(userDto.username, userDto.password);
  }

  @UseGuards(AuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }

  @UseGuards(AuthGuard)
  @Roles('admin')
  @Get('users')
  getAllUsers() {
    return this.userService.getAll();
  }
}
