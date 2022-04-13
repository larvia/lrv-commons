
export interface PayloadToken {
  active: boolean;
  roles: [string];
  companyId: string;
  firstName: string;
  lastName: string;
  email: string;
  language: string;
  iat: number;
  exp: number;
  sub: string;
  jti: string;
}