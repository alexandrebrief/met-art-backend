// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Pas besoin de "define" pour VITE_ variables, c'est automatique !
})
