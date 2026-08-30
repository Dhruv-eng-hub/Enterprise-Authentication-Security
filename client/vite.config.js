import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Forward API calls to the Express security server (keeps cookies same-origin)
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true
      }
    }
  }
});
