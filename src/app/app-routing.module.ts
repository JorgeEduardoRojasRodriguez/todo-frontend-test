import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AuthGuard } from './core/guards/auth.guard';

const routes: Routes = [
  {
    path: 'auth',
    loadChildren: () => import('./features/auth/auth.module').then(m => m.AuthModule)
  },
  {
    path: 'todos',
    loadChildren: () => import('./features/todos/todos.module').then(m => m.TodosModule),
    canActivate: [AuthGuard]
  },
  {
    path: '',
    redirectTo: '/todos',
    pathMatch: 'full'
  },
  {
    path: '**',
    redirectTo: '/todos'
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
