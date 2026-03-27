import { useEffect, useState, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { fetchApi } from '../api/client';
import { AlertCircle, FileCode2, Clock, Play, Loader2, RefreshCw, ChevronLeft, ChevronRight, ChevronDown, ChevronUp, Sparkles } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip } from 'recharts';

const COLORS: Record<string, string> = {
  BLOCKER: '#dc2626', CRITICAL: '#ef4444', MAJOR: '#f97316', MINOR: '#eab308', INFO: '#3b82f6',
};

const TOOLTIP_STYLE = {
  contentStyle: { backgroundColor: '#12122a', borderColor: '#252545', color: '#e2e8f0', borderRadius: '10px', fontSize: '13px' },
};

const MetricCard = ({ label, value, icon: Icon, iconColor = 'var(--accent)' }: any) => (
  <div className="stat">
    <div style={{ width: 40, height: 40, borderRadius: 10, flexShrink: 0, background: `${iconColor}18`, border: `1px solid ${iconColor}28`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Icon size={18} style={{ color: iconColor }} />
    </div>
    <div>
      <p style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.07em', color: 'var(--text-3)', marginBottom: 2 }}>{label}</p>
      <p style={{ fontSize: 22, fontWeight: 700, color: 'var(--text)', lineHeight: 1.1 }}>{value ?? '—'}</p>
    </div>
  </div>
);

const IssueCard = ({ issue }: { issue: any }) => {
  const [rec, setRec] = useState<string | null>(null);
  const [loadingRec, setLoadingRec] = useState(false);

  const fetchRecommendation = async () => {
    setLoadingRec(true);
    try {
      const res = await fetchApi(`/issues/${issue.id}/recommendation`);
      setRec(res.recommendation);
    } catch (err: any) {
      setRec(`Failed to get recommendation: ${err.message}`);
    } finally {
      setLoadingRec(false);
    }
  };

  return (
    <div className="card" style={{ padding: 16 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6 }}>
          <span className={`badge badge-${issue.severity.toLowerCase()}`}>{issue.severity}</span>
          <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--accent)', background: 'rgba(99,102,241,0.1)', padding: '2px 8px', borderRadius: 4 }}>{issue.rule_id}</span>
          <span style={{ fontSize: 11, color: 'var(--text-3)', border: '1px solid var(--border)', padding: '2px 8px', borderRadius: 4 }}>{issue.category}</span>
          {issue.owasp_category && (
            <span style={{ fontSize: 11, color: 'var(--red)', border: '1px solid rgba(239,68,68,.25)', background: 'rgba(239,68,68,.06)', padding: '2px 8px', borderRadius: 4, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={issue.owasp_category}>
              {issue.owasp_category.split('-')[0]}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--text-3)', background: 'var(--bg)', padding: '4px 10px', borderRadius: 6, border: '1px solid var(--border)' }}>
            {issue.file}:{issue.line}
          </span>
          {issue.severity === 'CRITICAL' && !rec && (
            <button
              onClick={fetchRecommendation}
              disabled={loadingRec}
              className="btn"
              style={{ padding: '4px 10px', fontSize: 11, background: 'rgba(139,92,246,0.1)', color: '#a78bfa', border: '1px solid rgba(139,92,246,0.25)', gap: 5 }}
            >
              {loadingRec ? <Loader2 size={11} className="spin" /> : <Sparkles size={11} />}
              {loadingRec ? 'Thinking…' : 'AI Fix'}
            </button>
          )}
        </div>
      </div>

      <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 8 }}>{issue.message}</p>

      {issue.suggestion && (
        <p style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 10, background: 'rgba(34,197,94,0.05)', border: '1px solid rgba(34,197,94,0.15)', borderLeft: '2px solid var(--green)', padding: '8px 12px', borderRadius: 6 }}>
          💡 {issue.suggestion}
        </p>
      )}

      {issue.code_snippet && (
        <div className="code-block">
          <pre style={{ whiteSpace: 'pre-wrap' }}>{issue.code_snippet}</pre>
        </div>
      )}

      {rec && (
        <div style={{ marginTop: 12, background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.2)', borderLeft: '3px solid #a78bfa', padding: '10px 14px', borderRadius: 8 }}>
          <p style={{ fontSize: 11, fontWeight: 700, color: '#a78bfa', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 5 }}>
            <Sparkles size={11} /> AI Recommendation
          </p>
          <p style={{ fontSize: 12, color: 'var(--text-2)', whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>{rec}</p>
        </div>
      )}
    </div>
  );
};

export const ProjectDetails = () => {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<any>(null);
  const [issuesData, setIssuesData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [page, setPage] = useState(1);
  const [showOthers, setShowOthers] = useState(false);
  const [othersPage, setOthersPage] = useState(1);
  const [othersData, setOthersData] = useState<any>(null);

  const loadData = useCallback(async () => {
    try {
      const [dash, issues] = await Promise.all([
        fetchApi(`/dashboard/${id}`),
        fetchApi(`/issues/${id}?severity=CRITICAL&page=${page}&per_page=50`),
      ]);
      setData(dash);
      setIssuesData(issues);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [id, page]);

  const loadOthers = useCallback(async () => {
    try {
      const res = await fetchApi(`/issues/${id}?page=${othersPage}&per_page=50&exclude_severity=CRITICAL`);
      setOthersData(res);
    } catch (err) {
      console.error(err);
    }
  }, [id, othersPage]);

  useEffect(() => { loadData(); }, [loadData]);
  useEffect(() => { if (showOthers) loadOthers(); }, [showOthers, loadOthers]);

  useEffect(() => {
    if (!data) return;
    const latestStatus = data?.scan_history?.[0]?.status;
    if (latestStatus !== 'running') return;
    const interval = setInterval(() => {
      fetchApi(`/projects/${id}`).then(res => {
        if (res.latest_scan?.status !== 'running') {
          clearInterval(interval);
          loadData();
        } else {
          loadData();
        }
      }).catch(console.error);
    }, 5000);
    return () => clearInterval(interval);
  }, [data, id, loadData]);

  const startScan = async () => {
    setScanning(true);
    try {
      await fetchApi('/scan-project', { method: 'POST', body: JSON.stringify({ project_id: id }) });
      setTimeout(loadData, 1000);
    } catch (err: any) {
      alert(`Failed to start scan: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  if (loading && !data) return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div className="skeleton" style={{ height: 80, borderRadius: 14 }} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 12 }}>
        {[1,2,3,4].map(i => <div key={i} className="skeleton" style={{ height: 80, borderRadius: 14 }} />)}
      </div>
      <div className="skeleton" style={{ height: 280, borderRadius: 14 }} />
      <div className="skeleton" style={{ height: 200, borderRadius: 14 }} />
    </div>
  );
  if (!data || data.error) return (
    <div className="card" style={{ padding: '3rem 2rem', textAlign: 'center' }}>
      <p style={{ color: 'var(--red)', fontWeight: 600 }}>Project not found or error loading data.</p>
    </div>
  );

  const { project, scan_history, severity_distribution, top_rules } = data;
  const latestScan = scan_history[0];
  const isRunning = latestScan?.status === 'running';

  const pieData = severity_distribution.map((d: any) => ({
    name: d.severity, value: d.count, color: COLORS[d.severity] ?? COLORS.INFO,
  }));

  return (
    <div className="fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 20, paddingBottom: 32 }}>
      {/* Header */}
      <div className="card" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text)', letterSpacing: '-.02em' }}>{project.name}</h1>
              <span className="badge badge-info">{project.language || 'UNKNOWN'}</span>
              {isRunning && (
                <span className="badge badge-running" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <Loader2 size={10} className="spin" /> Scanning
                </span>
              )}
            </div>
            <p style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>{project.path}</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <button onClick={loadData} className="btn-icon" title="Refresh"><RefreshCw size={16} /></button>
            <button onClick={startScan} disabled={scanning || isRunning} className="btn btn-primary">
              {scanning || isRunning ? <Loader2 size={15} className="spin" /> : <Play size={15} />}
              Run Scan
            </button>
          </div>
        </div>
      </div>

      {/* Metrics */}
      {latestScan ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 12 }}>
          <MetricCard label="Total Issues"  value={latestScan.total_issues}               icon={AlertCircle} iconColor="var(--accent)" />
          <MetricCard label="Critical"      value={latestScan.critical_count}             icon={AlertCircle} iconColor="var(--red)" />
          <MetricCard label="Files Scanned" value={latestScan.files_scanned}              icon={FileCode2}   iconColor="var(--cyan)" />
          <MetricCard label="Duration"      value={`${latestScan.scan_duration_seconds}s`} icon={Clock}      iconColor="var(--green)" />
        </div>
      ) : (
        <div className="card" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-2)', fontSize: 13 }}>
          No scans yet. Click "Run Scan" to start analyzing your code.
        </div>
      )}

      {/* Charts + Top Rules */}
      <div className="charts-grid" style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,2fr)', gap: 16 }}>
        <div className="card" style={{ padding: 20 }}>
          <p className="section-title" style={{ marginBottom: 16 }}>Severity Breakdown</p>
          <div style={{ height: 208 }}>
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={72} paddingAngle={4} dataKey="value" stroke="none">
                    {pieData.map((e: any, i: number) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <RechartsTooltip {...TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', fontSize: 13 }}>No issues found</div>
            )}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 16px', marginTop: 12 }}>
            {pieData.map((e: any) => (
              <div key={e.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-2)' }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: e.color, display: 'inline-block' }} />
                {e.name}: <strong style={{ color: 'var(--text)' }}>{e.value}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="card" style={{ padding: 20 }}>
          <p className="section-title" style={{ marginBottom: 16 }}>Top Triggered Rules</p>
          {top_rules.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {top_rules.slice(0, 5).map((rule: any) => (
                <div key={rule.rule_id} style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
                  background: 'var(--surface)', padding: '10px 14px', borderRadius: 10,
                  border: '1px solid var(--border)',
                }}>
                  <div style={{ minWidth: 0 }}>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--accent)', marginRight: 8 }}>{rule.rule_id}</span>
                    <span style={{ fontSize: 13, color: 'var(--text-2)' }}>{rule.rule_name}</span>
                  </div>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)', background: 'var(--surface-2)', padding: '3px 10px', borderRadius: 6, flexShrink: 0 }}>{rule.count}×</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', fontSize: 13 }}>No rules triggered yet</div>
          )}
        </div>
      </div>

      {/* Issues */}
      <div className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <p style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)' }}>Critical Issues</p>
          {issuesData?.total > 0 && (
            <span style={{ fontSize: 12, color: 'var(--text-3)', background: 'var(--surface)', padding: '3px 12px', borderRadius: 99 }}>{issuesData.total} critical</span>
          )}
        </div>

        {issuesData?.issues.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {issuesData.issues.map((issue: any) => (
              <IssueCard key={issue.id} issue={issue} />
            ))}

            {/* Critical pagination */}
            {(issuesData.total > 50) && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 16, borderTop: '1px solid var(--border)', marginTop: 4 }}>
                <p style={{ fontSize: 12, color: 'var(--text-3)' }}>Page {page} · {issuesData.total} critical</p>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button disabled={page === 1} onClick={() => setPage(p => p - 1)} className="btn btn-ghost" style={{ padding: '6px 12px', fontSize: 12 }}>
                    <ChevronLeft size={14} /> Prev
                  </button>
                  <button disabled={issuesData.issues.length < 50} onClick={() => setPage(p => p + 1)} className="btn btn-ghost" style={{ padding: '6px 12px', fontSize: 12 }}>
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="card" style={{ padding: '2rem', textAlign: 'center', border: '1.5px dashed var(--border-2)', color: 'var(--text-3)', fontSize: 13 }}>
            {latestScan ? '✅ No critical issues found.' : 'No issues to display.'}
          </div>
        )}

        {/* Other Issues toggle */}
        {latestScan && (latestScan.total_issues - (issuesData?.total ?? 0)) > 0 && (
          <div style={{ marginTop: 20, borderTop: '1px solid var(--border)', paddingTop: 16 }}>
            <button
              onClick={() => setShowOthers(v => !v)}
              className="btn btn-ghost"
              style={{ width: '100%', justifyContent: 'center', gap: 8, fontSize: 13 }}
            >
              {showOthers ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
              {showOthers ? 'Hide' : `Show ${latestScan.total_issues - (issuesData?.total ?? 0)} other issues`} (MAJOR · MINOR · INFO · BLOCKER)
            </button>

            {showOthers && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 14 }}>
                {othersData?.issues.map((issue: any) => (
                  <IssueCard key={issue.id} issue={issue} />
                ))}
                {!othersData && (
                  <div style={{ textAlign: 'center', padding: 20, color: 'var(--text-3)', fontSize: 13 }}>
                    <Loader2 size={16} className="spin" style={{ display: 'inline-block' }} />
                  </div>
                )}
                {othersData && othersData.total > 50 && (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 16, borderTop: '1px solid var(--border)', marginTop: 4 }}>
                    <p style={{ fontSize: 12, color: 'var(--text-3)' }}>Page {othersPage} · {othersData.total} issues</p>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button disabled={othersPage === 1} onClick={() => setOthersPage(p => p - 1)} className="btn btn-ghost" style={{ padding: '6px 12px', fontSize: 12 }}>
                        <ChevronLeft size={14} /> Prev
                      </button>
                      <button disabled={othersData.issues.length < 50} onClick={() => setOthersPage(p => p + 1)} className="btn btn-ghost" style={{ padding: '6px 12px', fontSize: 12 }}>
                        Next <ChevronRight size={14} />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
