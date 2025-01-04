import { Injectable } from '@nestjs/common';

@Injectable()
export class UsersService {
  private users = [
    {
      id: 1,
      username: 'john',
      password: 'john123',
      role: 'user',
    },
    {
      id: 2,
      username: 'jonas',
      password: 'jonas123',
      role: 'admin',
    },
  ];

  async findByUsername(username: string) {
    return this.users.find((user) => user.username === username);
  }

  async getAll() {
    return this.users;
  }
}
