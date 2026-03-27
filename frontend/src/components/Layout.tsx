import { useState } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { Shield, UploadCloud, Menu, X, Github, ChevronRight, Zap } from 'lucide-react';

const NAV = [
  { icon: UploadCloud, label: 'Check Code', to: '/' },
];

const PAGE_TITLES: Record<string, string> = {
  '/': 'Code Quality Checker',
};

const NavItem = ({ icon: Icon, label, to, active, onClick }: any) => (
  <Link to={to} onClick={onClick}
    style={{
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '9px 12px', borderRadius: 10,
      fontSize: 13.5, fontWeight: 500,
      textDecoration: 'none',
      transition: 'all .18s',
      color:      active ? '#fff' : 'var(--text-2)',
      background: active ? 'linear-gradient(135deg,rgba(99,102,241,.2),rgba(139,92,246,.15))' : 'transparent',
      border:     active ? '1px solid rgba(99,102,241,.35)' : '1px solid transparent',
      boxShadow:  active ? '0 2px 12px rgba(99,102,241,.15)' : 'none',
    }}
  >
    <Icon size={16} style={{ color: active ? 'var(--accent)' : 'var(--text-3)', flexShrink: 0 }} />
    {label}
  </Link>
);

export const Layout = () => {
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);

  const pageTitle =
    PAGE_TITLES[location.pathname] ??
    (location.pathname.startsWith('/projects/') ? 'Scan Results' : '');

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--bg)' }}>

      {/* Mobile overlay */}
      {open && (
        <div onClick={close} style={{
          position: 'fixed', inset: 0, zIndex: 40,
          background: 'rgba(0,0,0,.75)', backdropFilter: 'blur(6px)',
        }} />
      )}

      {/* ── Sidebar ─────────────────────────────────────────── */}
      <aside className={`sidebar${open ? ' sidebar-open' : ''}`}>
        {/* Logo */}
        <div style={{
          height: 56, display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', padding: '0 16px',
          borderBottom: '1px solid var(--border)', flexShrink: 0,
        }}>
          <Link to="/" onClick={close} style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' }}>
            <div style={{
              width: 30, height: 30, borderRadius: 8, flexShrink: 0,
              background: 'linear-gradient(135deg,var(--accent),var(--accent-2))',
              boxShadow: '0 0 16px rgba(99,102,241,.45)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Shield size={15} color="#fff" />
            </div>
            <span style={{ fontWeight: 700, fontSize: 14, color: 'var(--text)', letterSpacing: '-.01em' }}>
              Code<span style={{
                background: 'linear-gradient(90deg,var(--accent),var(--cyan))',
                WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
              }}>Quality</span>
            </span>
          </Link>
          <button onClick={close} className="btn-icon sidebar-close" style={{ padding: 5 }}>
            <X size={15} />
          </button>
        </div>

        {/* Nav links */}
        <nav style={{ flex: 1, padding: '16px 10px', display: 'flex', flexDirection: 'column', gap: 4, overflowY: 'auto' }}>
          <p style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.1em', color: 'var(--text-3)', padding: '0 12px', marginBottom: 6 }}>
            Menu
          </p>
          {NAV.map(({ icon, label, to }) => (
            <NavItem key={to} icon={icon} label={label} to={to}
              active={location.pathname === to}
              onClick={close}
            />
          ))}
        </nav>

        {/* Sidebar footer */}
        <div style={{ padding: 10, borderTop: '1px solid var(--border)', flexShrink: 0 }}>
          <div className="card" style={{ padding: '10px 12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>CodeQuality</p>
              <p style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 1 }}>v1.0.0</p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span className="pulse-dot" style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', display: 'inline-block' }} />
              <Zap size={12} style={{ color: 'var(--green)' }} />
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main area ───────────────────────────────────────── */}
      <main className="main-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0, position: 'relative' }}>

        {/* Ambient glow */}
        <div style={{
          position: 'absolute', top: -150, right: -150, width: 500, height: 500,
          background: 'radial-gradient(circle,rgba(99,102,241,.06) 0%,transparent 70%)',
          borderRadius: '50%', pointerEvents: 'none', zIndex: 0,
        }} />

        {/* ── Topbar ── */}
        <header style={{
          height: 56, display: 'flex', alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 20px',
          borderBottom: '1px solid var(--border)',
          background: 'rgba(8,8,18,.9)',
          backdropFilter: 'blur(20px)',
          flexShrink: 0, zIndex: 10, position: 'relative',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {/* Hamburger — mobile only */}
            <button className="btn-icon sidebar-toggle" onClick={() => setOpen(true)} style={{ padding: 7 }}>
              <Menu size={17} />
            </button>
            {/* Breadcrumb */}
            {pageTitle && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 12, color: 'var(--text-3)' }} className="breadcrumb-parent">CodeQuality</span>
                <ChevronRight size={12} style={{ color: 'var(--text-3)' }} className="breadcrumb-parent" />
                <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--text)' }}>{pageTitle}</span>
              </div>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <a href="https://github.com" target="_blank" rel="noreferrer" className="btn-icon" style={{ padding: 7 }}>
              <Github size={16} />
            </a>
            <div style={{
              width: 30, height: 30, borderRadius: '50%',
              background: 'linear-gradient(135deg,var(--accent),var(--accent-2))',
              boxShadow: '0 0 12px rgba(99,102,241,.4)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 11, fontWeight: 700, color: '#fff',
            }}>CQ</div>
          </div>
        </header>

        {/* ── Page content ── */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 'clamp(16px,2.5vw,28px)', position: 'relative', zIndex: 1 }}>
          <div style={{ maxWidth: 1280, margin: '0 auto' }}>
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
};
