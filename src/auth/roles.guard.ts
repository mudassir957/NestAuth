import {
    Injectable,
    CanActivate,
    ExecutionContext,
    ForbiddenException,
  } from '@nestjs/common';
  import { Reflector } from '@nestjs/core';
  
  @Injectable()
  export class RolesGuard implements CanActivate {
    constructor(private reflector: Reflector) {}
  
    canActivate(context: ExecutionContext): boolean {
      const requiredRoles = this.reflector.get<string[]>('roles', context.getHandler());
      
      // If no roles are defined, allow access
      if (!requiredRoles || requiredRoles.length === 0) {
        return true;
      }
  
      const request = context.switchToHttp().getRequest();
      const user = request.user;
  
      // Ensure user exists and their role matches at least one of the required roles
      if (!user || !requiredRoles.some((role) => user.role === role)) {
        throw new ForbiddenException('You do not have access to this resource');
      }
  
      return true;
    }
  }
  