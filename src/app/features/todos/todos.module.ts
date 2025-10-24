import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { SharedModule } from '@shared/shared.module';

import { TodoListComponent } from './todo-list/todo-list.component';
import { TodoFormDialogComponent } from './todo-form-dialog/todo-form-dialog.component';
import { TodoLayoutComponent } from './todo-layout/todo-layout.component';

const routes: Routes = [
  {
    path: '',
    component: TodoLayoutComponent,
    children: [
      {
        path: '',
        component: TodoListComponent
      }
    ]
  }
];

@NgModule({
  declarations: [
    TodoListComponent,
    TodoFormDialogComponent,
    TodoLayoutComponent
  ],
  imports: [
    SharedModule,
    RouterModule.forChild(routes)
  ]
})
export class TodosModule { }
