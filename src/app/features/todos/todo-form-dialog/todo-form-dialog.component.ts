import { Component, Inject, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { Todo, Prioridad } from '@core/models/todo.model';

@Component({
  selector: 'app-todo-form-dialog',
  templateUrl: './todo-form-dialog.component.html',
  styleUrls: ['./todo-form-dialog.component.scss']
})
export class TodoFormDialogComponent implements OnInit {
  todoForm!: FormGroup;
  isEditMode: boolean;
  prioridades = Object.values(Prioridad);

  constructor(
    private fb: FormBuilder,
    public dialogRef: MatDialogRef<TodoFormDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: Todo | null
  ) {
    this.isEditMode = !!data;
  }

  ngOnInit(): void {
    this.todoForm = this.fb.group({
      nombre: [this.data?.nombre || '', [Validators.required, Validators.minLength(3)]],
      prioridad: [this.data?.prioridad || Prioridad.MEDIA, [Validators.required]],
      finalizada: [this.data?.finalizada || false]
    });

    if (!this.isEditMode) {
      this.todoForm.removeControl('finalizada');
    }
  }

  onSubmit(): void {
    if (this.todoForm.invalid) {
      return;
    }

    this.dialogRef.close(this.todoForm.value);
  }

  onCancel(): void {
    this.dialogRef.close();
  }

  getErrorMessage(fieldName: string): string {
    const field = this.todoForm.get(fieldName);
    if (field?.hasError('required')) {
      return 'Este campo es requerido';
    }
    if (field?.hasError('minlength')) {
      const minLength = field.getError('minlength').requiredLength;
      return `Mínimo ${minLength} caracteres`;
    }
    return '';
  }
}
