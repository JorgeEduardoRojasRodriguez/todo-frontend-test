export enum Prioridad {
  BAJA = 'baja',
  MEDIA = 'media',
  ALTA = 'alta'
}

export interface Todo {
  id: string;
  nombre: string;
  prioridad: Prioridad;
  finalizada: boolean;
  fechaCreacion: Date;
  fechaActualizacion: Date;
}

export interface CreateTodoRequest {
  nombre: string;
  prioridad: Prioridad;
}

export interface UpdateTodoRequest {
  nombre?: string;
  prioridad?: Prioridad;
  finalizada?: boolean;
}

export interface TodoListResponse {
  data: Todo[];
  meta: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface TodoQueryParams {
  page?: number;
  limit?: number;
  prioridad?: Prioridad;
  finalizada?: boolean;
}
