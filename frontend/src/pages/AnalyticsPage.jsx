import React from 'react';
import { useAnalytics } from '../hooks';
import { Link } from 'react-router-dom';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

const VERDICT_COLORS = {
  SAFE: '#10b981',       // emerald-500
  SUSPICIOUS: '#f59e0b', // amber-500
  PHISHING: '#f43f5e',   // rose-500
};

export default function AnalyticsPage() {
  const { data, isLoading, error, refetch } = useAnalytics();

  if (isLoading) {
    return (
      <div className="max-w-6xl mx-auto px-6 py-8">
        <div className="mb-8">
          <div className="h-8 w-48 bg-panel rounded animate-pulse mb-2"></div>
          <div className="h-4 w-72 bg-panel rounded animate-pulse"></div>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="bg-panel border border-line rounded-lg p-6 h-28 animate-pulse"></div>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="bg-panel border border-line rounded-lg p-6 h-80 animate-pulse lg:col-span-1"></div>
          <div className="bg-panel border border-line rounded-lg p-6 h-80 animate-pulse lg:col-span-2"></div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-6xl mx-auto px-6 py-12">
        <div className="bg-rose-900/10 border border-rose-800/50 rounded-lg p-6 text-center">
          <h2 className="text-xl font-bold text-rose-400 mb-2">Unable to load security analytics</h2>
          <p className="text-rose-300 mb-6">{error}</p>
          <button
            onClick={() => refetch()}
            className="inline-flex items-center px-4 py-2 border border-rose-800 text-sm font-medium rounded-md text-rose-300 bg-rose-900/30 hover:bg-rose-900/50 focus:outline-none focus:ring-2 focus:ring-rose-500 transition-colors"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  const { summary, verdictDistribution, recentActivity } = data;

  if (summary.totalScans === 0) {
    return (
      <div className="max-w-6xl mx-auto px-6 py-16 text-center">
        <div className="mx-auto w-24 h-24 bg-panel border border-line rounded-full flex items-center justify-center mb-6">
          <svg className="w-10 h-10 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
          </svg>
        </div>
        <h2 className="text-2xl font-bold text-slate-100 mb-3">No security activity yet</h2>
        <p className="text-slate-400 mb-8 max-w-md mx-auto">
          Run your first URL or email scan to start building your security analytics and monitoring threat exposure.
        </p>
        <Link
          to="/"
          className="inline-flex items-center px-6 py-3 border border-transparent text-sm font-medium rounded-md text-slate-900 bg-accent hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent transition-colors"
        >
          Run a Scan
        </Link>
      </div>
    );
  }

  // Format data for Recharts
  const pieData = [
    { name: 'Safe', value: verdictDistribution.SAFE || 0, color: VERDICT_COLORS.SAFE },
    { name: 'Suspicious', value: verdictDistribution.SUSPICIOUS || 0, color: VERDICT_COLORS.SUSPICIOUS },
    { name: 'Phishing', value: verdictDistribution.PHISHING || 0, color: VERDICT_COLORS.PHISHING },
  ].filter(d => d.value > 0);

  const formatPercentage = (val) => {
    return `${val.toFixed(1)}%`;
  };

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-panel border border-line p-3 rounded shadow-lg text-sm">
          <p className="font-semibold text-slate-200 mb-1">{label}</p>
          <p className="text-slate-400">
            Scans: <span className="text-slate-100 font-medium">{payload[0].value}</span>
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-extrabold text-slate-100">Security Analytics</h1>
        <p className="mt-2 text-sm text-slate-400">
          Monitor your phishing detection activity and threat exposure.
        </p>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        
        {/* Total Scans */}
        <div className="bg-panel border border-line rounded-lg p-5 flex items-start justify-between">
          <div>
            <p className="text-sm font-medium text-slate-400 mb-1">Total Scans</p>
            <p className="text-2xl font-bold text-slate-100">{summary.totalScans.toLocaleString()}</p>
          </div>
          <div className="p-2 bg-blue-900/20 text-blue-400 rounded-md">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
          </div>
        </div>

        {/* Phishing Detected */}
        <div className="bg-panel border border-line rounded-lg p-5 flex items-start justify-between">
          <div>
            <p className="text-sm font-medium text-slate-400 mb-1">Phishing Detected</p>
            <p className="text-2xl font-bold text-rose-500">{summary.phishing.toLocaleString()}</p>
          </div>
          <div className="p-2 bg-rose-900/20 text-rose-500 rounded-md">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
        </div>

        {/* Phishing Rate */}
        <div className="bg-panel border border-line rounded-lg p-5 flex items-start justify-between">
          <div>
            <p className="text-sm font-medium text-slate-400 mb-1">Phishing Rate</p>
            <p className="text-2xl font-bold text-slate-100">{formatPercentage(summary.phishingRate)}</p>
          </div>
          <div className="p-2 bg-purple-900/20 text-purple-400 rounded-md">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M20.488 9H15V3.512A9.025 9.025 0 0120.488 9z" />
            </svg>
          </div>
        </div>

        {/* Safe Scans */}
        <div className="bg-panel border border-line rounded-lg p-5 flex items-start justify-between">
          <div>
            <p className="text-sm font-medium text-slate-400 mb-1">Safe Scans</p>
            <p className="text-2xl font-bold text-emerald-500">{summary.safe.toLocaleString()}</p>
          </div>
          <div className="p-2 bg-emerald-900/20 text-emerald-500 rounded-md">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
        </div>

      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Threat Distribution */}
        <div className="bg-panel border border-line rounded-lg p-6 lg:col-span-1 flex flex-col">
          <h2 className="text-lg font-semibold text-slate-100 mb-6">Threat Distribution</h2>
          <div className="flex-1 min-h-[250px] relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={5}
                  dataKey="value"
                  stroke="none"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#f8fafc' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 flex flex-col gap-2">
            {pieData.map((entry) => (
              <div key={entry.name} className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: entry.color }}></div>
                  <span className="text-slate-300">{entry.name}</span>
                </div>
                <span className="font-semibold text-slate-100">{entry.value.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-panel border border-line rounded-lg p-6 lg:col-span-2 flex flex-col">
          <h2 className="text-lg font-semibold text-slate-100 mb-6">Recent Activity</h2>
          <div className="flex-1 min-h-[300px]">
            {recentActivity && recentActivity.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={recentActivity} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis 
                    dataKey="date" 
                    tick={{ fill: '#94a3b8', fontSize: 12 }} 
                    axisLine={{ stroke: '#334155' }}
                    tickLine={{ stroke: '#334155' }}
                    tickFormatter={(val) => {
                      const date = new Date(val);
                      return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
                    }}
                  />
                  <YAxis 
                    tick={{ fill: '#94a3b8', fontSize: 12 }} 
                    axisLine={false}
                    tickLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: '#1e293b', opacity: 0.5 }} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} maxBarSize={50} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                No activity data available in the selected range.
              </div>
            )}
          </div>
        </div>

      </div>

    </div>
  );
}

