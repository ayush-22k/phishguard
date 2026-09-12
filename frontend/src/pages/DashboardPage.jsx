import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { useUrlScan, useEmailScan } from '../hooks';

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [scanType, setScanType] = useState('url');
  
  // URL Scan state
  const [urlInput, setUrlInput] = useState('');
  const { scanUrl, isLoading: isUrlLoading, error: urlError, data: urlData, reset: resetUrl } = useUrlScan();

  // Email Scan state
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const { scanEmail, isLoading: isEmailLoading, error: emailError, data: emailData, reset: resetEmail } = useEmailScan();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const handleUrlSubmit = async (e) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    await scanUrl(urlInput);
  };

  const handleEmailSubmit = async (e) => {
    e.preventDefault();
    if (!emailSubject.trim() && !emailBody.trim()) return;
    await scanEmail({ subject: emailSubject, body: emailBody });
  };

  const clearForm = () => {
    setUrlInput('');
    setEmailSubject('');
    setEmailBody('');
    resetUrl();
    resetEmail();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-8 gap-4">
        <div>
          <h1 className="text-3xl font-extrabold text-slate-100">Dashboard</h1>
          <p className="mt-1 text-sm text-slate-400">
            Welcome back, {user?.name || user?.email}!
          </p>
        </div>
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <button
            onClick={() => navigate('/analytics')}
            className="flex-1 sm:flex-none inline-flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-slate-900 bg-accent hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent transition-colors"
          >
            Analytics
          </button>
          <button
            onClick={handleLogout}
            className="flex-1 sm:flex-none inline-flex justify-center items-center px-4 py-2 border border-line text-sm font-medium rounded-md text-slate-200 bg-panel hover:bg-surface focus:outline-none focus:ring-2 focus:ring-accent transition-colors"
          >
            Sign out
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Scan Input Section */}
        <div className="lg:col-span-2 bg-panel rounded-lg shadow-sm border border-line overflow-hidden flex flex-col">
          <div className="border-b border-line px-6 py-4 flex gap-6">
            <button
              onClick={() => { setScanType('url'); clearForm(); }}
              className={`text-sm font-semibold pb-4 -mb-4 border-b-2 transition-colors ${
                scanType === 'url' ? 'border-accent text-accent' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Scan URL
            </button>
            <button
              onClick={() => { setScanType('email'); clearForm(); }}
              className={`text-sm font-semibold pb-4 -mb-4 border-b-2 transition-colors ${
                scanType === 'email' ? 'border-accent text-accent' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Scan Email
            </button>
          </div>
          
          <div className="p-6 flex-1">
            {scanType === 'url' ? (
              <form onSubmit={handleUrlSubmit} className="space-y-4">
                <div>
                  <label htmlFor="url" className="block text-sm font-medium text-slate-300 mb-1">Target URL</label>
                  <input
                    type="url"
                    id="url"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="https://example.com"
                    className="block w-full bg-[#091626] border border-line rounded-md py-2 px-3 text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-accent focus:border-accent sm:text-sm"
                    required
                  />
                </div>
                {urlError && (
                  <div className="text-sm text-rose-400 bg-rose-900/10 p-3 rounded-md border border-rose-800/50">
                    {urlError}
                  </div>
                )}
                {urlData && (
                  <div className="text-sm text-emerald-400 bg-emerald-900/10 p-3 rounded-md border border-emerald-800/50 flex justify-between items-center">
                    <span>Scan completed successfully.</span>
                    <button type="button" onClick={() => navigate(`/history/${urlData.id}`)} className="text-accent hover:underline font-medium">View Report</button>
                  </div>
                )}
                <button
                  type="submit"
                  disabled={isUrlLoading || !urlInput.trim()}
                  className="w-full sm:w-auto inline-flex justify-center items-center px-6 py-2.5 border border-transparent text-sm font-medium rounded-md text-slate-900 bg-accent hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[#091626] focus:ring-accent disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {isUrlLoading ? 'Analyzing...' : 'Analyze URL'}
                </button>
              </form>
            ) : (
              <form onSubmit={handleEmailSubmit} className="space-y-4">
                <div>
                  <label htmlFor="subject" className="block text-sm font-medium text-slate-300 mb-1">Email Subject (Optional)</label>
                  <input
                    type="text"
                    id="subject"
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    placeholder="Urgent Action Required"
                    className="block w-full bg-[#091626] border border-line rounded-md py-2 px-3 text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-accent focus:border-accent sm:text-sm"
                  />
                </div>
                <div>
                  <label htmlFor="body" className="block text-sm font-medium text-slate-300 mb-1">Email Body</label>
                  <textarea
                    id="body"
                    rows={6}
                    value={emailBody}
                    onChange={(e) => setEmailBody(e.target.value)}
                    placeholder="Paste the suspicious email content here..."
                    className="block w-full bg-[#091626] border border-line rounded-md py-2 px-3 text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-accent focus:border-accent sm:text-sm resize-none"
                    required
                  />
                </div>
                {emailError && (
                  <div className="text-sm text-rose-400 bg-rose-900/10 p-3 rounded-md border border-rose-800/50">
                    {emailError}
                  </div>
                )}
                {emailData && (
                  <div className="text-sm text-emerald-400 bg-emerald-900/10 p-3 rounded-md border border-emerald-800/50 flex justify-between items-center">
                    <span>Scan completed successfully.</span>
                    <button type="button" onClick={() => navigate(`/history/${emailData.id}`)} className="text-accent hover:underline font-medium">View Report</button>
                  </div>
                )}
                <button
                  type="submit"
                  disabled={isEmailLoading || (!emailSubject.trim() && !emailBody.trim())}
                  className="w-full sm:w-auto inline-flex justify-center items-center px-6 py-2.5 border border-transparent text-sm font-medium rounded-md text-slate-900 bg-accent hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[#091626] focus:ring-accent disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {isEmailLoading ? 'Analyzing...' : 'Analyze Email'}
                </button>
              </form>
            )}
          </div>
        </div>

        {/* Quick Stats / Info Widget */}
        <div className="bg-panel rounded-lg shadow-sm border border-line p-6 flex flex-col justify-center text-center">
           <div className="w-12 h-12 bg-accent/10 text-accent rounded-full flex items-center justify-center mx-auto mb-4">
             <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
             </svg>
           </div>
           <h3 className="text-lg font-medium text-slate-100 mb-2">Threat Intelligence</h3>
           <p className="text-sm text-slate-400 mb-6">
             Our security engine evaluates multiple heuristics and known signatures to detect sophisticated phishing attempts.
           </p>
           <button
             onClick={() => navigate('/history')}
             className="inline-flex justify-center items-center px-4 py-2 border border-line text-sm font-medium rounded-md text-slate-200 bg-surface hover:bg-[#091626] transition-colors"
           >
             View Scan History
           </button>
        </div>
      </div>
    </div>
  );
}
