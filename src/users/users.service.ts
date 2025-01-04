import { Injectable } from '@nestjs/common';

@Injectable()
export class UsersService {
  private users = [
    {
      id: 1,
      username: 'john',
      password: 'john123',
    },
    {
      id: 2,
      username: 'jonas',
      password: 'jonas123',
    },
  ];

  async findByUsername(username: string) {
    return this.users.find((user) => user.username === username);
  }
}
