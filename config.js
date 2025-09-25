// vite.config.js
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/poc': {
        target: 'http://localhost:5050',
        changeOrigin: true
      },
      '/api': {
        target: 'http://localhost:5050',
        changeOrigin: true
      }
    }
  }
})