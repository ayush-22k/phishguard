import { Outlet } from 'react-router-dom';

function MainLayout() {
  return (
    <div className="min-h-screen bg-surface text-slate-100">
      <header className="border-b border-line bg-[#091626]">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
          <a className="flex items-center gap-3 font-semibold tracking-tight" href="/">
            <span className="grid h-8 w-8 place-items-center rounded-md border border-accent/50 bg-accent/10 text-sm text-accent">P</span>
            PhishGuard
          </a>
          <span className="text-sm text-slate-400">Security analysis platform</span>
        </div>
      </header>
      <main>
        <Outlet />
      </main>
    </div>
  );
}

export default MainLayout;
