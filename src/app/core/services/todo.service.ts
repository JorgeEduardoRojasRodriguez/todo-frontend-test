import { Injectable, signal } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { environment } from '@environments/environment';
import {
  Todo,
  CreateTodoRequest,
  UpdateTodoRequest,
  TodoListResponse,
  TodoQueryParams
} from '../models/todo.model';

@Injectable({
  providedIn: 'root'
})
export class TodoService {
  private apiUrl = `${environment.apiUrl}/todo`;

  todos = signal<Todo[]>([]);

  private refreshSubject = new BehaviorSubject<void>(undefined);
  public refresh$ = this.refreshSubject.asObservable();

  constructor(private http: HttpClient) {}

  createTodo(data: CreateTodoRequest): Observable<{ message: string; todo: Todo }> {
    return this.http.post<{ message: string; todo: Todo }>(`${this.apiUrl}/create`, data).pipe(
      tap(() => this.refreshSubject.next())
    );
  }

  getTodos(params?: TodoQueryParams): Observable<TodoListResponse> {
    let httpParams = new HttpParams();

    if (params) {
      if (params.page) httpParams = httpParams.set('page', params.page.toString());
      if (params.limit) httpParams = httpParams.set('limit', params.limit.toString());
      if (params.prioridad) httpParams = httpParams.set('prioridad', params.prioridad);
      if (params.finalizada !== undefined) {
        httpParams = httpParams.set('finalizada', params.finalizada.toString());
      }
    }

    return this.http.get<TodoListResponse>(`${this.apiUrl}/list`, { params: httpParams }).pipe(
      tap(response => this.todos.set(response.data))
    );
  }

  getTodoById(id: string): Observable<Todo> {
    return this.http.get<Todo>(`${this.apiUrl}/list/${id}`);
  }

  updateTodo(id: string, data: UpdateTodoRequest): Observable<{ message: string; todo: Todo }> {
    return this.http.patch<{ message: string; todo: Todo }>(`${this.apiUrl}/update/${id}`, data).pipe(
      tap(() => this.refreshSubject.next())
    );
  }

  deleteTodo(id: string): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.apiUrl}/list/${id}`).pipe(
      tap(() => this.refreshSubject.next())
    );
  }

  toggleTodoStatus(id: string, finalizada: boolean): Observable<{ message: string; todo: Todo }> {
    return this.updateTodo(id, { finalizada });
  }
}
