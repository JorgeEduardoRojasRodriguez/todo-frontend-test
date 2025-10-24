import { Component, OnInit, OnDestroy } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { PageEvent } from '@angular/material/paginator';
import { Subject, takeUntil, switchMap } from 'rxjs';
import { TodoService } from '@core/services/todo.service';
import { Todo, Prioridad, TodoQueryParams } from '@core/models/todo.model';
import { TodoFormDialogComponent } from '../todo-form-dialog/todo-form-dialog.component';

@Component({
  selector: 'app-todo-list',
  templateUrl: './todo-list.component.html',
  styleUrls: ['./todo-list.component.scss']
})
export class TodoListComponent implements OnInit, OnDestroy {
  todos: Todo[] = [];
  loading = false;
  destroy$ = new Subject<void>();

  totalTodos = 0;
  pageSize = 10;
  pageIndex = 0;
  pageSizeOptions = [5, 10, 25, 50];

  prioridadFilter: Prioridad | '' = '';
  finalizadaFilter: 'true' | 'false' | '' = '';
  prioridades = Object.values(Prioridad);

  displayedColumns: string[] = ['nombre', 'prioridad', 'finalizada', 'fechaCreacion', 'acciones'];

  constructor(
    private todoService: TodoService,
    private dialog: MatDialog,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    this.loadTodos();

    this.todoService.refresh$
      .pipe(
        takeUntil(this.destroy$),
        switchMap(() => {
          this.loading = true;
          return this.todoService.getTodos(this.getQueryParams());
        })
      )
      .subscribe({
        next: (response) => {
          this.todos = response.data;
          this.totalTodos = response.meta.total;
          this.loading = false;
        },
        error: () => {
          this.loading = false;
        }
      });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  loadTodos(): void {
    this.loading = true;
    this.todoService.getTodos(this.getQueryParams()).subscribe({
      next: (response) => {
        this.todos = response.data;
        this.totalTodos = response.meta.total;
        this.loading = false;
      },
      error: (error) => {
        this.loading = false;
        this.showError('Error al cargar tareas');
      }
    });
  }

  getQueryParams(): TodoQueryParams {
    const params: TodoQueryParams = {
      page: this.pageIndex + 1,
      limit: this.pageSize
    };

    if (this.prioridadFilter) {
      params.prioridad = this.prioridadFilter as Prioridad;
    }

    if (this.finalizadaFilter !== '') {
      params.finalizada = this.finalizadaFilter === 'true';
    }

    return params;
  }

  onPageChange(event: PageEvent): void {
    this.pageIndex = event.pageIndex;
    this.pageSize = event.pageSize;
    this.loadTodos();
  }

  onFilterChange(): void {
    this.pageIndex = 0;
    this.loadTodos();
  }

  clearFilters(): void {
    this.prioridadFilter = '';
    this.finalizadaFilter = '';
    this.onFilterChange();
  }

  openCreateDialog(): void {
    const dialogRef = this.dialog.open(TodoFormDialogComponent, {
      width: '500px',
      data: null
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.todoService.createTodo(result).subscribe({
          next: (response) => {
            this.showSuccess(response.message);
          },
          error: () => {
            this.showError('Error al crear tarea');
          }
        });
      }
    });
  }

  openEditDialog(todo: Todo): void {
    const dialogRef = this.dialog.open(TodoFormDialogComponent, {
      width: '500px',
      data: todo
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.todoService.updateTodo(todo.id, result).subscribe({
          next: (response) => {
            this.showSuccess(response.message);
          },
          error: () => {
            this.showError('Error al actualizar tarea');
          }
        });
      }
    });
  }

  toggleTodoStatus(todo: Todo): void {
    this.todoService.toggleTodoStatus(todo.id, !todo.finalizada).subscribe({
      next: (response) => {
        this.showSuccess(response.message);
      },
      error: () => {
        this.showError('Error al actualizar estado');
      }
    });
  }

  deleteTodo(todo: Todo): void {
    if (confirm(`¿Estás seguro de eliminar la tarea "${todo.nombre}"?`)) {
      this.todoService.deleteTodo(todo.id).subscribe({
        next: (response) => {
          this.showSuccess(response.message);
        },
        error: () => {
          this.showError('Error al eliminar tarea');
        }
      });
    }
  }

  getPrioridadClass(prioridad: Prioridad): string {
    return `prioridad-${prioridad}`;
  }

  getPrioridadIcon(prioridad: Prioridad): string {
    switch (prioridad) {
      case Prioridad.ALTA:
        return 'arrow_upward';
      case Prioridad.MEDIA:
        return 'drag_handle';
      case Prioridad.BAJA:
        return 'arrow_downward';
      default:
        return 'remove';
    }
  }

  private showSuccess(message: string): void {
    this.snackBar.open(message, 'Cerrar', {
      duration: 3000,
      horizontalPosition: 'end',
      verticalPosition: 'top'
    });
  }

  private showError(message: string): void {
    this.snackBar.open(message, 'Cerrar', {
      duration: 5000,
      horizontalPosition: 'end',
      verticalPosition: 'top',
      panelClass: ['error-snackbar']
    });
  }
}
