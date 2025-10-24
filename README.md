# Todo App - Frontend

Cliente web para la gestión de tareas desarrollado con Angular 17 y Angular Material.

## Requisitos Previos

- Node.js 18+
- npm
- Backend API corriendo en `http://localhost:3000`

## Cómo Levantar el Proyecto

1. **Clonar el repositorio**
   ```bash
   git clone <url-del-repositorio>
   cd todo-app-frontend
   ```

2. **Instalar dependencias**
   ```bash
   npm install
   ```

3. **Configurar la URL del backend** (opcional)

   Si tu backend está en una URL diferente, edita `src/environments/environment.ts`:
   ```typescript
   export const environment = {
     production: false,
     apiUrl: 'http://localhost:3000/v1'
   };
   ```

4. **Iniciar el servidor de desarrollo**
   ```bash
   npm start
   ```

   La aplicación estará disponible en `http://localhost:4200`

5. **Para compilar para producción**
   ```bash
   npm run build
   ```

   Los archivos compilados estarán en la carpeta `dist/`
