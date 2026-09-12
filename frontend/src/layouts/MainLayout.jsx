import { Outlet, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import logo from '../assets/logo.png';

function MainLayout() {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-surface text-slate-100 flex flex-col">
      <header className="border-b border-line bg-[#091626]">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
          <Link className="flex items-center font-semibold tracking-tight" to="/">
            <img src={logo} alt="PhishGuard" className="h-10 object-contain" />
          </Link>
          
          {user && (
            <div className="flex items-center">
              <nav className="hidden md:flex items-center gap-6 text-sm font-medium mr-4">
                <Link to="/dashboard" className="text-slate-300 hover:text-slate-100 transition-colors">Dashboard</Link>
                <Link to="/analytics" className="text-slate-300 hover:text-slate-100 transition-colors">Analytics</Link>
                <Link to="/history" className="text-slate-300 hover:text-slate-100 transition-colors">History</Link>
              </nav>
              <div className="md:hidden flex items-center gap-4 text-sm font-medium">
                <Link to="/dashboard" className="text-slate-300 hover:text-slate-100 transition-colors">Scan</Link>
                <Link to="/analytics" className="text-slate-300 hover:text-slate-100 transition-colors">Analytics</Link>
                <Link to="/history" className="text-slate-300 hover:text-slate-100 transition-colors">History</Link>
              </div>
            </div>
          )}

          <div className="hidden sm:flex items-center gap-4">
            <span className="text-sm text-slate-400">Security analysis platform</span>
          </div>
        </div>
      </header>
      <main className="flex-1">
        <Outlet />
      </main>
    </div>
  );
}

export default MainLayout;
