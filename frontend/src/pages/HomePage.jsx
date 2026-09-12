import { Link } from 'react-router-dom';
import logo from '../assets/logo.png';

function HomePage() {
  return (
    <div className="flex flex-col min-h-screen">
      <main className="flex-grow">
        <section className="mx-auto max-w-6xl px-6 py-20 sm:py-28">
          <div className="max-w-3xl">
            <style>{`
              @keyframes fadeIn {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
              }
              .animate-fade-in { animation: fadeIn 0.8s ease-out forwards; }
              .animate-fade-in-delayed { animation: fadeIn 0.8s ease-out 0.2s forwards; opacity: 0; }
              .animate-fade-in-cards { animation: fadeIn 0.8s ease-out 0.4s forwards; opacity: 0; }
            `}</style>
            
            <div className="inline-flex items-center rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-sm font-medium text-accent mb-6 animate-pulse">
              <span>🚀 Now with AI Security Analysis</span>
            </div>
            
            <h1 className="text-4xl font-semibold tracking-tight text-white sm:text-6xl animate-fade-in">
              Defend Against Phishing with <span className="text-accent">Intelligent Precision</span>
            </h1>
            
            <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-300 animate-fade-in-delayed">
              PhishGuard is a secure, explainable platform for assessing suspicious URLs and emails. 
              Our deterministic detection engine is now paired with advanced AI to explain threats clearly, keeping your digital life safe.
            </p>
            
            <div className="mt-10 flex items-center gap-x-6 animate-fade-in-delayed">
              <Link
                to="/register"
                className="rounded-md bg-accent px-6 py-3 text-sm font-semibold text-surface shadow-sm hover:bg-accent/90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent transition-transform hover:scale-105"
              >
                Sign Up Free
              </Link>
              <Link to="/login" className="text-sm font-semibold leading-6 text-slate-300 hover:text-white transition-colors flex items-center gap-1 group">
                Log In <span aria-hidden="true" className="group-hover:translate-x-1 transition-transform">→</span>
              </Link>
            </div>
          </div>
          
          <div className="mt-20 grid gap-6 sm:grid-cols-3 animate-fade-in-cards">
            {[
              { title: 'Explainable Analysis', desc: 'Understand exactly why a threat was flagged with AI-powered insights.' },
              { title: 'Secure by Design', desc: 'Strict data boundaries ensure your information remains protected.' },
              { title: 'Deterministic Detection', desc: 'Core security heuristics you can trust, enhanced by AI capabilities.' }
            ].map((item, i) => (
              <div 
                className="rounded-xl border border-line bg-panel p-6 text-slate-300 transition-all duration-300 hover:-translate-y-2 hover:shadow-xl hover:shadow-accent/10" 
                key={item.title}
              >
                <span className="mb-4 block h-1 w-10 rounded bg-accent" />
                <h3 className="text-lg font-semibold text-white mb-2">{item.title}</h3>
                <p className="text-sm leading-relaxed text-slate-400">{item.desc}</p>
              </div>
            ))}
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-line bg-surface/50 py-10 mt-auto">
        <div className="mx-auto max-w-6xl px-6 flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-slate-500">
          <div className="flex items-center gap-2">
            <img src={logo} alt="PhishGuard" className="h-8 object-contain" />
          </div>
          <p>© {new Date().getFullYear()} PhishGuard. All rights reserved.</p>
          <div className="flex gap-6">
            <a href="#" className="hover:text-accent transition-colors">Privacy Policy</a>
            <a href="#" className="hover:text-accent transition-colors">Terms of Service</a>
            <a href="#" className="hover:text-accent transition-colors">Contact Support</a>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default HomePage;
