import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        // Routes API calls through the Java Spring Boot backend on port 9090
        // (Java delegates ML inference to the Python engine on port 8000)
        target: 'http://localhost:9090',
        changeOrigin: true,
      },
    },
  },
});
