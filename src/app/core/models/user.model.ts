export interface User {
  id: string;
  nombre: string;
  email: string;
}

export interface AuthResponse {
  message: string;
  user: User;
  token: string;
}

export interface RegisterRequest {
  nombre: string;
  email: string;
  password: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}
