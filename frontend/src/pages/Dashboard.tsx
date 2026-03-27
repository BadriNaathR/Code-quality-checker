import { useEffect, useState } from 'react';
import { fetchApi } from '../api/client';
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Tooltip as RTooltip, CartesianGrid,
} from 'recharts';
import { Bug, Activity, Cpu, ShieldAlert, BarChart2, Plus } from 'lucide-react';
import { Link } from 'react-router-dom';

const SEV_COLORS: Record<string, string> = {
  BLOCKER: '#dc2626', CRITICAL: '#ef4444', MAJOR: '#f97316', MINOR: '#eab308', INFO: '#3b82f6',
};

const TIP = {
  contentStyle: { background: '#0e0e1c', border: '1px solid rgba(255,255,255,.08)', borderRadius: 10, fontSize: 12, color: '#f1f5f9' },
  itemStyle:    { color: '#f1f5f9' },
  cursor:       { fill: 'rgba(255,255,255,.03)' },
};

const Stat = ({ label, value, icon: Icon, color }: any) => (
  <div className="stat">
    <div
      className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0"
      style={{ background: `${color}18`, border: `1px solid ${color}28` }}
    >
      <Icon size={20} style={{ color }} />
    </div>
    <div>
      <p className="text-[11px] font-semibold uppercase tracking-wider mb-0.5" style={{ color: 'var(--text-3)' }}>{label}</p>
      <p className="text-2xl font-bold" style={{ color: 'var(--text)', lineHeight: 1.1 }}>{value ?? '—'}</p>
    </div>
  </div>
);

const ScanStatus = ({ status }: { status: string }) => {
  const cls: Record<string, string> = {
    completed: 'badge-success', failed: 'badge-failed', running: 'badge-running',
  };
  return <span className={`badge ${cls[status] ?? 'badge-running'}`}>{status}</span>;
};

const ChartCard = ({ title, icon: Icon, iconColor, children }: any) => (
  <div className="card p-5 flex flex-col">
    <div className="flex items-center gap-2 mb-5">
      <Icon size={16} style={{ color: iconColor }} />
      <span className="text-sm font-semibold" style={{ color: 'var(--text)' }}>{title}</span>
    </div>
    {children}
  </div>
);

export const Dashboard = () => {
  const [data, setData]     = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchApi('/dashboard').then(setData).catch(console.error).finally(() => setLoading(false));
  }, []);

  if (loading) return (
    <div className="space-y-5">
      <div className="skeleton h-8 w-48 rounded-lg" />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(200px,1fr))', gap: 16 }}>
        {[1,2,3].map(i => <div key={i} className="skeleton h-24 rounded-2xl" />)}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(320px,1fr))', gap: 16 }}>
        <div className="skeleton h-80 rounded-2xl" />
        <div className="skeleton h-80 rounded-2xl" />
      </div>
      <div className="skeleton h-64 rounded-2xl" />
    </div>
  );

  if (!data) return (
    <div className="flex items-center justify-center h-64">
      <p style={{ color: 'var(--text-2)' }}>Failed to load dashboard data.</p>
    </div>
  );

  const sevData = data.severity_distribution
    .map((d: any) => ({ name: d.severity, value: d.count, color: SEV_COLORS[d.severity] ?? SEV_COLORS.INFO }))
    .sort((a: any, b: any) => b.value - a.value);

  const catData = data.category_distribution
    .map((d: any) => ({ name: d.category.replace(/_/g, ' '), value: d.count }))
    .sort((a: any, b: any) => b.value - a.value);

  const BAR_COLORS = ['#6366f1', '#8b5cf6', '#a78bfa', '#c4b5fd', '#ddd6fe'];

  return (
    <div className="fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 20, paddingBottom: 32 }}>

      {/* ── Page header ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text)', letterSpacing: '-.02em' }}>
            Platform Overview
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text-2)' }}>
            Aggregated metrics across all scanned projects
          </p>
        </div>
        <Link to="/projects/new" className="btn btn-primary">
          <Plus size={15} /> New Project
        </Link>
      </div>

      {/* ── Stats ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(190px,1fr))', gap: 12 }}>
        <Stat label="Total Projects" value={data.overview.total_projects} icon={Activity} color="var(--accent)" />
        <Stat label="Total Scans"    value={data.overview.total_scans}    icon={Cpu}      color="var(--cyan)"   />
        <Stat label="Total Issues"   value={data.overview.total_issues}   icon={Bug}      color="var(--orange)" />
      </div>

      {/* ── Charts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(300px,1fr))', gap: 16 }}>

        {/* Severity donut */}
        <ChartCard title="Issue Severity" icon={ShieldAlert} iconColor="var(--orange)">
          <div style={{ height: 220 }}>
            {sevData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sevData} cx="50%" cy="50%" innerRadius={65} outerRadius={90}
                    paddingAngle={3} dataKey="value" stroke="none">
                    {sevData.map((e: any, i: number) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <RTooltip {...TIP} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm" style={{ color: 'var(--text-3)' }}>
                No data yet
              </div>
            )}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 16px', marginTop: 12, justifyContent: 'center' }}>
            {sevData.map((e: any) => (
              <div key={e.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-2)' }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: e.color, display: 'inline-block', flexShrink: 0 }} />
                {e.name} <strong style={{ color: 'var(--text)' }}>{e.value}</strong>
              </div>
            ))}
          </div>
        </ChartCard>

        {/* Category bar */}
        <ChartCard title="Issue Categories" icon={BarChart2} iconColor="var(--cyan)">
          <div style={{ flex: 1, minHeight: 220 }}>
            {catData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={catData} layout="vertical" margin={{ top: 0, right: 16, left: 8, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,.05)" horizontal={false} />
                  <XAxis type="number" stroke="transparent" tick={{ fill: 'var(--text-3)', fontSize: 11 }} />
                  <YAxis dataKey="name" type="category" stroke="transparent" width={100}
                    tick={{ fill: 'var(--text-2)', fontSize: 11 }} />
                  <RTooltip {...TIP} />
                  <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                    {catData.map((_: any, i: number) => (
                      <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-sm" style={{ color: 'var(--text-3)' }}>
                No data yet
              </div>
            )}
          </div>
        </ChartCard>
      </div>

      {/* ── Recent Scans ── */}
      <div className="card p-5">
        <p className="text-sm font-semibold mb-4" style={{ color: 'var(--text)' }}>Recent Scans</p>
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Project</th>
                <th>Status</th>
                <th>Issues</th>
                <th className="hide-md">Critical / Major</th>
                <th className="hide-md">Duration</th>
                <th className="hide-sm">Date</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_scans.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-3)' }}>
                    No scans yet
                  </td>
                </tr>
              ) : data.recent_scans.map((s: any) => (
                <tr key={s.id}>
                  <td>
                    <Link
                      to={`/projects/${s.project_id}`}
                      style={{ fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-2)' }}
                      className="hover:text-[var(--accent)] transition-colors"
                    >
                      {s.project_id.split('-')[0]}
                    </Link>
                  </td>
                  <td><ScanStatus status={s.status} /></td>
                  <td style={{ fontWeight: 600, color: 'var(--text)' }}>{s.total_issues}</td>
                  <td className="hide-md">
                    <span style={{ color: 'var(--red)', fontWeight: 600 }}>{s.critical_count}</span>
                    <span style={{ color: 'var(--text-3)', margin: '0 4px' }}>/</span>
                    <span style={{ color: 'var(--orange)', fontWeight: 600 }}>{s.major_count}</span>
                  </td>
                  <td className="hide-md" style={{ color: 'var(--text-2)', fontSize: 13 }}>{s.scan_duration_seconds}s</td>
                  <td className="hide-sm" style={{ color: 'var(--text-3)', fontSize: 12 }}>
                    {new Date(s.started_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
