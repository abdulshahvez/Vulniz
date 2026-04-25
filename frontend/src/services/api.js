import axios from 'axios';

/**
 * API Service — handles all communication with the backend.
 */
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
});

/** Start a new scan */
export async function startScan(targetUrl, attacks) {
  const { data } = await api.post('/scan', { targetUrl, attacks });
  return data;
}

/** Get scan status / results */
export async function getScanStatus(scanId) {
  const { data } = await api.get(`/scan/${scanId}`);
  return data;
}

/** List all scans */
export async function listScans() {
  const { data } = await api.get('/scan');
  return data;
}

/** Get JSON report */
export async function getReport(scanId) {
  const { data } = await api.get(`/report/${scanId}`);
  return data;
}

/** Download PDF report */
export function getPdfUrl(scanId) {
  return `/api/report/${scanId}/pdf`;
}

/** Discover endpoints */
export async function discoverEndpoints(baseUrl) {
  const { data } = await api.post('/scan/discover', { baseUrl });
  return data;
}

/**
 * Connect to SSE stream for real-time progress.
 * Returns an EventSource instance — caller must close it.
 */
export function connectScanStream(scanId, handlers = {}) {
  const es = new EventSource(`/api/scan/${scanId}/stream`);

  if (handlers.onProgress) es.addEventListener('progress', (e) => handlers.onProgress(JSON.parse(e.data)));
  if (handlers.onLog) es.addEventListener('log', (e) => handlers.onLog(JSON.parse(e.data)));
  if (handlers.onComplete) es.addEventListener('complete', (e) => { handlers.onComplete(JSON.parse(e.data)); es.close(); });
  if (handlers.onError) es.addEventListener('error', (e) => { handlers.onError(e); es.close(); });
  if (handlers.onStatus) es.addEventListener('status', (e) => handlers.onStatus(JSON.parse(e.data)));

  return es;
}

export default api;
