import { useState } from 'react'
import { Activity, Box, FileCode2, LayoutDashboard, Menu, Moon, ShieldCheck, Sun, X, FileBarChart2 } from 'lucide-react'

const navigation = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'scanner', label: 'Image Scanner', icon: Box },
  { id: 'manifest', label: 'Manifest Auditor', icon: FileCode2 },
  { id: 'reports', label: 'Reports', icon: FileBarChart2 },
]

export default function AppLayout({ activePage, onNavigate, children, theme, onToggleTheme }) {
  const [mobileOpen, setMobileOpen] = useState(false)
  const navigate = (page) => { onNavigate(page); setMobileOpen(false) }

  return <div className={`app-frame ${theme === 'dark' ? 'theme-dark' : ''}`}>
    <aside className={`app-sidebar ${mobileOpen ? 'is-open' : ''}`}>
      <div className="sidebar-brand"><div className="brand-shield"><ShieldCheck size={19} /></div><div><strong>VigiDock</strong><span>AI security console</span></div><button className="sidebar-close" onClick={() => setMobileOpen(false)} aria-label="Close menu"><X size={18} /></button></div>
      <div className="sidebar-section-label">Workspace</div>
      <nav className="app-nav" aria-label="Primary navigation">{navigation.map(({ id, label, icon: Icon }) => <button key={id} className={activePage === id ? 'is-active' : ''} onClick={() => navigate(id)}><Icon size={17} />{label}{id === 'dashboard' && <span className="nav-pulse" />}</button>)}</nav>
      <div className="sidebar-status"><div className="status-line"><span className="status-dot" /> API connected</div><p>Security signals for every release.</p><div className="status-meta"><Activity size={14} /> Trivy engine ready</div></div>
    </aside>
    {mobileOpen && <button className="sidebar-overlay" onClick={() => setMobileOpen(false)} aria-label="Close navigation" />}
    <main className="app-main"><header className="app-topbar"><button className="mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={21} /></button><div className="topbar-context"><span>Workspace</span><b>/</b><strong>{navigation.find((item) => item.id === activePage)?.label}</strong></div><div className="topbar-tools"><span className="environment-pill"><i /> Local environment</span><button className="theme-toggle" onClick={onToggleTheme} aria-label="Toggle theme">{theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}</button><div className="user-avatar">VD</div></div></header><div className="app-content">{children}</div></main>
  </div>
}
