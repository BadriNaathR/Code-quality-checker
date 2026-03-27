import { useState, useEffect } from 'react';
import { fetchApi } from '../api/client';
import { useNavigate } from 'react-router-dom';
import { Loader2, UploadCloud, FileArchive, X, Clock, Code2, Trash2 } from 'lucide-react';

const SESSION_KEY = 'cq_history';
const SESSION_TTL = 5 * 60 * 1000; // 5 minutes

type HistoryEntry = { id: string; name: string; language: string; checkedAt: string };

function getHistory(): HistoryEntry[] {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return [];
    const entries: HistoryEntry[] = JSON.parse(raw);
    const cutoff = Date.now() - SESSION_TTL;
    const valid = entries.filter(h => new Date(h.checkedAt).getTime() > cutoff);
    if (valid.length !== entries.length) sessionStorage.setItem(SESSION_KEY, JSON.stringify(valid));
    return valid;
  } catch { return []; }
}

function addHistory(entry: HistoryEntry) {
  const prev = getHistory().filter(h => h.id !== entry.id);
  sessionStorage.setItem(SESSION_KEY, JSON.stringify([entry, ...prev].slice(0, 20)));
}

const LANG_LABELS: Record<string, string> = {
  auto: 'Auto Detect',
  python: 'Python',
  javascript: 'JavaScript / TypeScript',
  sql: 'SQL',
  csharp: 'C# / .NET',
};

export const Projects = () => null;

export const NewProject = () => {
  const [name, setName] = useState('');
  const [language, setLanguage] = useState('auto');
  const [loading, setLoading] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [history, setHistory] = useState<HistoryEntry[]>(getHistory);
  const navigate = useNavigate();

  const MAX_ZIP_SIZE = 200 * 1024 * 1024;

  // Auto-expire history entries every 30s and delete expired projects from backend
  useEffect(() => {
    const interval = setInterval(() => {
      const before = getHistory();
      const cutoff = Date.now() - SESSION_TTL;
      const expired = before.filter(h => new Date(h.checkedAt).getTime() <= cutoff);
      expired.forEach(h => fetchApi(`/projects/${h.id}`, { method: 'DELETE' }).catch(() => {}));
      setHistory(getHistory());
    }, 30_000);
    return () => clearInterval(interval);
  }, []);

  const validateAndSetFile = (f: File | null) => {
    if (!f) return;
    if (!f.name.endsWith('.zip')) return alert('Only .zip files are supported.');
    if (f.size > MAX_ZIP_SIZE) return alert('File exceeds the 200 MB limit.');
    setFile(f);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    validateAndSetFile(e.dataTransfer.files[0]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return alert('Please select a ZIP file.');
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append('name', name);
      fd.append('language', language);
      fd.append('file', file);
      const res = await fetchApi('/projects/upload', { method: 'POST', body: fd });
      await fetchApi('/scan-project', { method: 'POST', body: JSON.stringify({ project_id: res.id }) });
      const entry: HistoryEntry = { id: res.id, name, language, checkedAt: new Date().toISOString() };
      addHistory(entry);
      setHistory(getHistory());
      navigate(`/projects/${res.id}`);
    } catch (err: any) {
      alert(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const removeHistory = (id: string) => {
    fetchApi(`/projects/${id}`, { method: 'DELETE' }).catch(() => {});
    const updated = getHistory().filter(h => h.id !== id);
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(updated));
    setHistory(updated);
  };

  return (
    <div className="fade-up" style={{ maxWidth: 560, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 20, paddingBottom: 32 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text)', letterSpacing: '-.02em' }}>Check Code Quality</h1>
        <p style={{ fontSize: 13, color: 'var(--text-2)', marginTop: 4 }}>Upload a ZIP archive to scan</p>
      </div>

      <div className="card" style={{ padding: 24 }}>
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>Project Name</label>
            <input required type="text" value={name} onChange={e => setName(e.target.value)} className="input" placeholder="e.g. Authentication Service" />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>Source Code Archive</label>
            <div
              className={`dropzone${dragOver ? ' over' : ''}${file ? ' filled' : ''}`}
              onClick={() => document.getElementById('zip-upload')?.click()}
              onDragOver={e => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
            >
              {file ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
                  <FileArchive size={32} style={{ color: 'var(--accent)' }} />
                  <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>{file.name}</p>
                  <p style={{ fontSize: 11, color: 'var(--text-2)' }}>{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                  <button type="button" onClick={e => { e.stopPropagation(); setFile(null); }}
                    style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--red)', background: 'none', border: 'none', cursor: 'pointer', marginTop: 4 }}>
                    <X size={12} /> Remove
                  </button>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
                  <UploadCloud size={32} style={{ color: 'var(--text-3)' }} />
                  <p style={{ fontSize: 13, color: 'var(--text-2)' }}>Drop your ZIP here or <span style={{ color: 'var(--accent)' }}>browse</span></p>
                  <p style={{ fontSize: 11, color: 'var(--text-3)' }}>Only .zip files · Max 200 MB</p>
                </div>
              )}
              <input id="zip-upload" type="file" accept=".zip" style={{ display: 'none' }} onChange={e => validateAndSetFile(e.target.files?.[0] ?? null)} />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 500, color: 'var(--text-2)', marginBottom: 6 }}>Primary Language</label>
            <select value={language} onChange={e => setLanguage(e.target.value)} className="input">
              <option value="auto">🔍 Auto Detect (all languages)</option>
              <option value="python">Python</option>
              <option value="javascript">JavaScript / TypeScript</option>
              <option value="sql">SQL</option>
              <option value="csharp">C# / .NET</option>
            </select>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', paddingTop: 4 }}>
            <button type="submit" disabled={loading} className="btn btn-primary">
              {loading ? <><Loader2 size={14} className="spin" /> Scanning…</> : 'Check Quality'}
            </button>
          </div>
        </form>
      </div>

      {history.length > 0 && (
        <div className="card" style={{ padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Clock size={14} style={{ color: 'var(--text-3)' }} /> Session History
              <span style={{ fontSize: 11, color: 'var(--text-3)', fontWeight: 400 }}>(clears after 5 min)</span>
            </p>
            <button onClick={() => {
                getHistory().forEach(h => fetchApi(`/projects/${h.id}`, { method: 'DELETE' }).catch(() => {}));
                sessionStorage.removeItem(SESSION_KEY);
                setHistory([]);
              }}
              className="btn btn-ghost" style={{ fontSize: 11, padding: '4px 10px', color: 'var(--text-3)' }}>
              Clear all
            </button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {history.map(h => {
              const expiresIn = Math.max(0, Math.ceil((new Date(h.checkedAt).getTime() + SESSION_TTL - Date.now()) / 1000));
              const mins = Math.floor(expiresIn / 60);
              const secs = expiresIn % 60;
              return (
                <div key={h.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
                  background: 'var(--surface)', padding: '10px 14px', borderRadius: 10, border: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                    <Code2 size={15} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                    <div style={{ minWidth: 0 }}>
                      <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.name}</p>
                      <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 1 }}>
                        {LANG_LABELS[h.language] ?? h.language} · {new Date(h.checkedAt).toLocaleTimeString()} · expires in {mins}m {secs}s
                      </p>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                    <button onClick={() => navigate(`/projects/${h.id}`)} className="btn" style={{ fontSize: 11, padding: '4px 10px' }}>View</button>
                    <button onClick={() => removeHistory(h.id)} className="btn-icon" style={{ color: 'var(--text-3)' }} title="Remove">
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
