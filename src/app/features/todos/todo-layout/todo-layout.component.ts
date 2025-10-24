import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '@core/services/auth.service';

@Component({
  selector: 'app-todo-layout',
  templateUrl: './todo-layout.component.html',
  styleUrls: ['./todo-layout.component.scss']
})
export class TodoLayoutComponent {
  currentUser = this.authService.currentUser;

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  logout(): void {
    this.authService.logout();
  }
}
