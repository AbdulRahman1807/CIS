import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // forwards /api/* to the Python webui.py backend (run separately:
    // `python3 -m audit_agent.webui --port 8010`) so the browser only
    // ever talks to the Vite origin — avoids CORS entirely, since
    // webui.py sets no Access-Control-Allow-Origin headers.
    // NOTE: port 8000 is commonly taken by Docker Desktop's own proxy
    // on macOS — 8010 was picked specifically to avoid that collision.
    proxy: {
      '/api': 'http://localhost:8010',
    },
  },
})
