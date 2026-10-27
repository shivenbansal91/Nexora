import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ReactLenis } from 'lenis/react';
import AppLayout from './layouts/AppLayout';
import Dashboard from './pages/Dashboard/Dashboard';
import IncidentsList from './pages/Incidents/IncidentsList';
import LiveActivity from './pages/LiveActivity/LiveActivity';
import CorrelationPage from './pages/Correlation/CorrelationPage';
import AnalyticsPage from './pages/Analytics/AnalyticsPage';
import InfrastructurePage from './pages/Infrastructure/InfrastructurePage';
import { LiveProvider } from './live/LiveContext';
import 'lenis/dist/lenis.css';
import './index.css';

function App() {
  return (
    <ReactLenis root options={{ autoRaf: true, lerp: 0.08, smoothWheel: true }}>
      <LiveProvider>
        <Router>
          <Routes>
            <Route path="/" element={<AppLayout />}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard"      element={<Dashboard />} />
              <Route path="live"           element={<LiveActivity />} />
              <Route path="correlation"    element={<CorrelationPage />} />
              <Route path="incidents"      element={<IncidentsList />} />
              <Route path="analytics"      element={<AnalyticsPage />} />
              <Route path="infrastructure" element={<InfrastructurePage />} />
              <Route path="*" element={
                <div className="flex items-center justify-center h-full text-sm text-neutral-400">
                  Page under construction.
                </div>
              } />
            </Route>
          </Routes>
        </Router>
      </LiveProvider>
    </ReactLenis>
  );
}

export default App;
