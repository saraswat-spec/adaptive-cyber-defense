import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavView } from './components/Sidebar';
import { ExplainabilityModal } from './components/ExplainabilityModal';
import { DashboardView } from './views/DashboardView';
import { TrafficMonitorView } from './views/TrafficMonitorView';
import { AlertsView } from './views/AlertsView';
import { SimulationLabView } from './views/SimulationLabView';
import { AdaptiveConfigView } from './views/AdaptiveConfigView';
import { ModelAnalyticsView } from './views/ModelAnalyticsView';
import {
  FlowRecord,
  Alert,
  SimulationScenario,
  SimulationRun,
  AdaptiveThreshold,
  ModelAnalytics,
  FeatureImportance,
  AlertStatus
} from './types';
import { api } from './services/api';

export const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<NavView>('dashboard');
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);
  const [simulationRuns, setSimulationRuns] = useState<SimulationRun[]>([]);
  const [adaptiveThresholds, setAdaptiveThresholds] = useState<AdaptiveThreshold[]>([]);
  const [baselineProfile, setBaselineProfile] = useState<any>(null);
  const [analytics, setAnalytics] = useState<ModelAnalytics | null>(null);
  const [featureImportances, setFeatureImportances] = useState<FeatureImportance[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');

  // Real-time Traffic series for charts
  const [trafficSeries, setTrafficSeries] = useState<Array<{ time: string; observedPPS: number; simulatedPPS: number }>>([]);

  const isInitialLoad = useRef(true);

  // Initial Data Fetching
  const refreshAll = async () => {
    try {
      const [
        flowsData,
        alertsData,
        statsData,
        scenariosData,
        runsData,
        thresholdsData,
        baselineData,
        analyticsData,
        featuresData
      ] = await Promise.all([
        api.getFlows(50, 0, sourceFilter),
        api.getAlerts(),
        api.getStats(),
        api.getScenarios(),
        api.getSimulationRuns(),
        api.getThresholds(),
        api.getBaseline(),
        api.getModelAnalytics(),
        api.getFeatureImportances()
      ]);

      setFlows(flowsData);
      setAlerts(alertsData);
      setStats(statsData);
      setScenarios(scenariosData);
      setSimulationRuns(runsData);
      setAdaptiveThresholds(thresholdsData);
      setBaselineProfile(baselineData);
      setAnalytics(analyticsData);
      setFeatureImportances(featuresData);

      // Append to traffic series
      const nowStr = new Date().toLocaleTimeString();
      const obsPPS = flowsData
        .filter((f) => f.data_source === 'OBSERVED')
        .reduce((sum, f) => sum + (f.flow_packets_per_sec ?? f.flow_packets_per_second ?? 0), 0) / Math.max(1, flowsData.filter((f) => f.data_source === 'OBSERVED').length);
      const simPPS = flowsData
        .filter((f) => f.data_source === 'SIMULATED')
        .reduce((sum, f) => sum + (f.flow_packets_per_sec ?? f.flow_packets_per_second ?? 0), 0) / Math.max(1, flowsData.filter((f) => f.data_source === 'SIMULATED').length);

      setTrafficSeries((prev) => {
        const next = [...prev, { time: nowStr, observedPPS: Math.round(obsPPS), simulatedPPS: Math.round(simPPS) }];
        return next.slice(-20); // Keep last 20 snapshots
      });
    } catch (e) {
      console.error('Error fetching SOC telemetry:', e);
    }
  };

  useEffect(() => {
    if (isInitialLoad.current) {
      isInitialLoad.current = false;
      refreshAll();
    }

    // Real-time polling fallback / interval
    const interval = setInterval(async () => {
      try {
        const [latestFlows, latestAlerts, latestStats, latestRuns] = await Promise.all([
          api.getFlows(50, 0, sourceFilter),
          api.getAlerts(),
          api.getStats(),
          api.getSimulationRuns()
        ]);
        setFlows(latestFlows);
        setAlerts(latestAlerts);
        setStats(latestStats);
        setSimulationRuns(latestRuns);

        const nowStr = new Date().toLocaleTimeString();
        const obsList = latestFlows.filter((f) => f.data_source === 'OBSERVED');
        const simList = latestFlows.filter((f) => f.data_source === 'SIMULATED');
        const obsPPS = obsList.length > 0
          ? obsList.reduce((s, f) => s + f.flow_packets_per_sec, 0) / obsList.length
          : 0;
        const simPPS = simList.length > 0
          ? simList.reduce((s, f) => s + f.flow_packets_per_sec, 0) / simList.length
          : 0;

        setTrafficSeries((prev) => {
          const next = [...prev, { time: nowStr, observedPPS: Math.round(obsPPS), simulatedPPS: Math.round(simPPS) }];
          return next.slice(-20);
        });
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 2500);

    return () => clearInterval(interval);
  }, [sourceFilter]);

  const handleUpdateAlertStatus = async (alertId: string, status: AlertStatus) => {
    try {
      const updated = await api.updateAlertStatus(alertId, status);
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(updated);
      }
    } catch (err) {
      console.error('Failed to update alert status:', err);
    }
  };

  const handleAlertUpdatedFromModal = (updated: Alert) => {
    setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
    setSelectedAlert(updated);
    api.getThresholds().then(setAdaptiveThresholds);
  };

  const threatLevel = alerts.length > 0 && alerts[0].risk_score >= 80 ? 'CRITICAL'
    : alerts.length > 0 && alerts[0].risk_score >= 60 ? 'HIGH'
    : alerts.length > 0 && alerts[0].risk_score >= 35 ? 'MEDIUM'
    : 'LOW';

  const unresolvedAlertsCount = alerts.filter((a) => a.status === 'NEW').length;

  return (
    <div className="min-h-screen bg-[#080b11] text-slate-100 flex flex-col font-sans">
      <Navbar
        threatLevel={threatLevel}
        activeAlertsCount={unresolvedAlertsCount}
      />

      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          currentView={currentView}
          onSelectView={setCurrentView}
          unresolvedAlertsCount={unresolvedAlertsCount}
        />

        <main className="flex-1 overflow-y-auto p-6">
          {currentView === 'dashboard' && (
            <DashboardView
              alerts={alerts}
              flows={flows}
              stats={stats}
              trafficSeries={trafficSeries}
              onSelectAlert={setSelectedAlert}
              onNavigateToSimulation={() => setCurrentView('simulation')}
            />
          )}

          {currentView === 'monitor' && (
            <TrafficMonitorView
              flows={flows}
              activeSourceFilter={sourceFilter}
              onFilterChange={(src) => setSourceFilter(src)}
            />
          )}

          {currentView === 'alerts' && (
            <AlertsView
              alerts={alerts}
              onSelectAlert={setSelectedAlert}
              onUpdateStatus={handleUpdateAlertStatus}
            />
          )}

          {currentView === 'simulation' && (
            <SimulationLabView
              scenarios={scenarios}
              runs={simulationRuns}
              onSimulationLaunched={async () => {
                const runs = await api.getSimulationRuns();
                setSimulationRuns(runs);
              }}
            />
          )}

          {currentView === 'adaptive' && (
            <AdaptiveConfigView
              thresholds={adaptiveThresholds}
              baselineProfile={baselineProfile}
              onThresholdsUpdated={async () => {
                const thresholds = await api.getThresholds();
                setAdaptiveThresholds(thresholds);
              }}
            />
          )}

          {currentView === 'models' && (
            <ModelAnalyticsView
              analytics={analytics}
              featureImportances={featureImportances}
            />
          )}
        </main>
      </div>

      {/* Forensic Inspection & XAI Modal */}
      <ExplainabilityModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onAlertUpdated={handleAlertUpdatedFromModal}
      />
    </div>
  );
};
