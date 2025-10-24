import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-auth-layout',
  templateUrl: './auth-layout.component.html',
  styleUrls: ['./auth-layout.component.scss']
})
export class AuthLayoutComponent {
  @Input() title: string = '';
  @Input() subtitle: string = '';
  @Input() visualTitle: string = '';
  @Input() visualDescription: string = '';
  @Input() visualIcon: string = 'checklist_rtl';
}
