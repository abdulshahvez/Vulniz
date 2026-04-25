import React, { useState, useCallback } from 'react';
import Header from './components/Header.jsx';
import ScanForm from './components/ScanForm.jsx';
import ScanProgress from './components/ScanProgress.jsx';
import ResultsDashboard from './components/ResultsDashboard.jsx';
import LandingInfo from './components/LandingInfo.jsx';
import FeedbackForm from './components/FeedbackForm.jsx';
import { startScan, connectScanStream, getScanStatus } from './services/api.js';

/**
 * App — Root component orchestrating the scan lifecycle.
 *
 * States: idle → scanning → completed / error
 */
export default function App() {
  const [phase, setPhase] = useState('idle'); // idle | scanning | completed | error
  const [scanId, setScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [currentAttack, setCurrentAttack] = useState(null);
  const [logs, setLogs] = useState([]);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [eventSource, setEventSource] = useState(null);

  const handleStartScan = useCallback(async (targetUrl, attacks) => {
    try {
      setError(null);
      setPhase('scanning');
      setProgress(0);
      setLogs([]);
      setResults(null);
      setCurrentAttack(null);

      const { job } = await startScan(targetUrl, attacks);
      setScanId(job.id);

      // Connect SSE stream
      const es = connectScanStream(job.id, {
        onStatus: (data) => {
          setProgress(data.progress || 0);
          setCurrentAttack(data.currentAttack);
          if (data.logs) setLogs(data.logs);
        },
        onProgress: (data) => {
          setProgress(data.progress || 0);
          setCurrentAttack(data.currentAttack);
        },
        onLog: (entry) => {
          setLogs((prev) => [...prev, entry]);
        },
        onComplete: async (data) => {
          setProgress(100);
          setCurrentAttack(null);
          // Fetch full results
          try {
            const full = await getScanStatus(job.id);
            setResults(full);
          } catch {
            setResults(data);
          }
          setPhase('completed');
        },
        onError: (e) => {
          if (e && e.data) {
            try {
              const data = JSON.parse(e.data);
              if (data.error) {
                setError(data.error);
                setPhase('error');
                return;
              }
            } catch {}
          }
          
          setError('Connection to scan stream lost. Fetching results…');
          // Fallback: poll for results
          setTimeout(async () => {
            try {
              const full = await getScanStatus(job.id);
              if (full.status === 'completed') {
                setResults(full);
                setPhase('completed');
                setError(null);
              } else if (full.status === 'failed') {
                setError(full.error || 'Scan failed.');
                setPhase('error');
              }
            } catch (err) {
              setError('Scan failed. Please try again.');
              setPhase('error');
            }
          }, 2000);
        },
      });
      setEventSource(es);
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to start scan.');
      setPhase('error');
    }
  }, []);

  const handleReset = useCallback(() => {
    if (eventSource) eventSource.close();
    setPhase('idle');
    setScanId(null);
    setProgress(0);
    setCurrentAttack(null);
    setLogs([]);
    setResults(null);
    setError(null);
    setEventSource(null);
  }, [eventSource]);

  return (
    <div className="app">
      <Header />

      {error && <div className="error-msg">⚠ {error}</div>}

      {(phase === 'idle' || phase === 'error') && (
        <>
          <ScanForm onSubmit={handleStartScan} disabled={phase === 'scanning'} />
          <LandingInfo />
        </>
      )}

      {phase === 'scanning' && (
        <ScanProgress
          progress={progress}
          currentAttack={currentAttack}
          logs={logs}
        />
      )}

      {phase === 'completed' && results && (
        <ResultsDashboard results={results} scanId={scanId} onReset={handleReset} />
      )}

      {/* Show feedback form at the bottom, unless currently scanning */}
      {phase !== 'scanning' && <FeedbackForm />}
    </div>
  );
}
