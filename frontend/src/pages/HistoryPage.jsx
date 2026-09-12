import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useScanHistory } from '../hooks/useScanHistory';
import Modal from '../components/Modal';

function formatDate(isoString) {
  if (!isoString) return '';
  const date = new Date(isoString);
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function truncateString(str, maxLength = 60) {
  if (!str) return '';
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength) + '...';
}

function VerdictBadge({ verdict }) {
  let colors = 'bg-surface text-slate-300 border-line';
  if (verdict === 'SAFE' || verdict === 'BENIGN') {
    colors = 'bg-emerald-900/30 text-emerald-400 border-emerald-800/50';
  } else if (verdict === 'SUSPICIOUS') {
    colors = 'bg-amber-900/30 text-amber-400 border-amber-800/50';
  } else if (verdict === 'PHISHING' || verdict === 'MALICIOUS') {
    colors = 'bg-rose-900/30 text-rose-400 border-rose-800/50';
  }

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold border ${colors}`}>
      {verdict || 'UNKNOWN'}
    </span>
  );
}

export default function HistoryPage() {
  const navigate = useNavigate();
  const location = useLocation();

  // Filter state
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [verdict, setVerdict] = useState('');
  const [scanType, setScanType] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');

  // Deletion modals state
  const [scanToDelete, setScanToDelete] = useState(null);
  const [isClearModalOpen, setIsClearModalOpen] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [notification, setNotification] = useState(null);

  const showNotification = (msg, isError = false) => {
    setNotification({ msg, isError });
    setTimeout(() => setNotification(null), 5000);
  };

  useEffect(() => {
    if (location.state?.deleted) {
      showNotification('Scan deleted successfully.');
      // Clear location state to prevent re-triggering on reload
      navigate(location.pathname, { replace: true, state: {} });
    }
  }, [location.state, navigate, location.pathname]);

  // Debounce search
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearch(search);
    }, 400);
    return () => clearTimeout(handler);
  }, [search]);

  // Hook for API
  const { scans, pagination, isLoading, error, fetchHistory, refetch, deleteScan, clearHistory } = useScanHistory({
    page: 1,
    limit: 20,
  });

  // Whenever filters change, reset to page 1
  useEffect(() => {
    let fromIso = undefined;
    let toIso = undefined;

    if (from) {
      try { fromIso = new Date(from).toISOString(); } catch(e) {}
    }
    if (to) {
      try { toIso = new Date(to).toISOString(); } catch(e) {}
    }

    fetchHistory({
      page: 1,
      search: debouncedSearch || undefined,
      verdict: verdict || undefined,
      scanType: scanType || undefined,
      from: fromIso,
      to: toIso,
    });
  }, [debouncedSearch, verdict, scanType, from, to, fetchHistory]);

  const handlePageChange = (newPage) => {
    fetchHistory({ page: newPage });
  };

  const handleReset = () => {
    setSearch('');
    setDebouncedSearch('');
    setVerdict('');
    setScanType('');
    setFrom('');
    setTo('');
  };

  const hasFiltersActive = Boolean(debouncedSearch || verdict || scanType || from || to);

  const confirmDeleteScan = async () => {
    if (!scanToDelete) return;
    setIsDeleting(true);
    const result = await deleteScan(scanToDelete);
    setIsDeleting(false);
    
    if (result.success) {
      setScanToDelete(null);
      showNotification('Scan deleted successfully.');
      
      // If we deleted the last item on the current page (and not page 1), move to previous page
      if (scans.length === 1 && pagination.page > 1) {
        handlePageChange(pagination.page - 1);
      } else {
        refetch();
      }
    } else {
      setScanToDelete(null);
      showNotification('Unable to delete this scan. Please try again.', true);
    }
  };

  const confirmClearHistory = async () => {
    setIsDeleting(true);
    const result = await clearHistory();
    setIsDeleting(false);

    if (result.success) {
      setIsClearModalOpen(false);
      handleReset(); // Reset filters to go back to clean slate
      showNotification('Scan history cleared successfully.');
    } else {
      setIsClearModalOpen(false);
      showNotification('Unable to clear scan history. Please try again.', true);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-8 relative">
      
      {notification && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-md shadow-lg border ${notification.isError ? 'bg-rose-900/80 border-rose-800 text-rose-200' : 'bg-emerald-900/80 border-emerald-800 text-emerald-200'}`}>
          {notification.msg}
        </div>
      )}

      {/* Delete Modals */}
      <Modal
        isOpen={Boolean(scanToDelete)}
        onClose={() => setScanToDelete(null)}
        onConfirm={confirmDeleteScan}
        title="Delete scan?"
        message="Are you sure you want to permanently delete this scan? This action cannot be undone."
        confirmText="Delete Scan"
        isDestructive={true}
        isLoading={isDeleting}
      />

      <Modal
        isOpen={isClearModalOpen}
        onClose={() => setIsClearModalOpen(false)}
        onConfirm={confirmClearHistory}
        title="Clear scan history?"
        message="This will permanently delete all of your saved scan history. This action cannot be undone."
        confirmText="Clear History"
        isDestructive={true}
        isLoading={isDeleting}
      />

      {/* Header */}
      <div className="sm:flex sm:items-center sm:justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Scan History</h1>
          <p className="mt-2 text-sm text-slate-400">
            Review and inspect your previous phishing detection scans.
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex space-x-3">
          <button
            onClick={() => setIsClearModalOpen(true)}
            disabled={scans.length === 0 && !hasFiltersActive}
            className="inline-flex items-center px-4 py-2 border border-rose-900/50 shadow-sm text-sm font-medium rounded-md text-rose-400 bg-panel hover:bg-rose-900/20 focus:outline-none focus:ring-2 focus:ring-rose-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Clear History
          </button>
          <button
            onClick={() => refetch()}
            className="inline-flex items-center px-4 py-2 border border-line shadow-sm text-sm font-medium rounded-md text-slate-100 bg-panel hover:bg-surface focus:outline-none focus:ring-2 focus:ring-accent"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-panel p-4 rounded-lg shadow-sm border border-line mb-6 space-y-4 sm:space-y-0 sm:flex sm:space-x-4 flex-wrap items-end">
        <div className="w-full sm:w-auto flex-1 min-w-[200px]">
          <label htmlFor="search" className="block text-sm font-medium text-slate-300 mb-1">
            Search
          </label>
          <input
            type="text"
            id="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search scans..."
            className="block w-full rounded-md shadow-sm sm:text-sm p-2 bg-surface border border-line text-slate-100 placeholder-slate-500 focus:border-accent focus:ring-1 focus:ring-accent outline-none"
          />
        </div>

        <div className="w-full sm:w-auto">
          <label htmlFor="verdict" className="block text-sm font-medium text-slate-300 mb-1">
            Verdict
          </label>
          <select
            id="verdict"
            value={verdict}
            onChange={(e) => setVerdict(e.target.value)}
            className="block w-full rounded-md shadow-sm sm:text-sm p-2 bg-surface border border-line text-slate-100 focus:border-accent focus:ring-1 focus:ring-accent outline-none appearance-none"
          >
            <option value="">All Verdicts</option>
            <option value="SAFE">SAFE</option>
            <option value="SUSPICIOUS">SUSPICIOUS</option>
            <option value="PHISHING">PHISHING</option>
          </select>
        </div>

        <div className="w-full sm:w-auto">
          <label htmlFor="scanType" className="block text-sm font-medium text-slate-300 mb-1">
            Scan Type
          </label>
          <select
            id="scanType"
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            className="block w-full rounded-md shadow-sm sm:text-sm p-2 bg-surface border border-line text-slate-100 focus:border-accent focus:ring-1 focus:ring-accent outline-none appearance-none"
          >
            <option value="">All Types</option>
            <option value="URL">URL</option>
            <option value="EMAIL">EMAIL</option>
          </select>
        </div>

        <div className="w-full sm:w-auto">
          <label htmlFor="from" className="block text-sm font-medium text-slate-300 mb-1">
            From
          </label>
          <input
            type="datetime-local"
            id="from"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            className="block w-full rounded-md shadow-sm sm:text-sm p-2 bg-surface border border-line text-slate-100 focus:border-accent focus:ring-1 focus:ring-accent outline-none color-scheme-dark"
            style={{ colorScheme: 'dark' }}
          />
        </div>

        <div className="w-full sm:w-auto">
          <label htmlFor="to" className="block text-sm font-medium text-slate-300 mb-1">
            To
          </label>
          <input
            type="datetime-local"
            id="to"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            className="block w-full rounded-md shadow-sm sm:text-sm p-2 bg-surface border border-line text-slate-100 focus:border-accent focus:ring-1 focus:ring-accent outline-none color-scheme-dark"
            style={{ colorScheme: 'dark' }}
          />
        </div>

        <div className="w-full sm:w-auto pt-4 sm:pt-0">
          <button
            onClick={handleReset}
            className="w-full sm:w-auto inline-flex items-center px-4 py-2 border border-line text-sm font-medium rounded-md text-slate-100 bg-surface hover:bg-line focus:outline-none focus:ring-2 focus:ring-accent shadow-sm transition-colors"
          >
            Reset Filters
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="bg-panel shadow-sm border border-line rounded-lg overflow-hidden flex flex-col">
        {error ? (
          <div className="p-10 text-center">
            <h3 className="text-lg font-medium text-slate-100 mb-2">Unable to load scan history.</h3>
            <p className="text-slate-400 mb-4">{error}</p>
            <button
              onClick={() => refetch()}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-surface bg-accent hover:bg-accent/90"
            >
              Retry
            </button>
          </div>
        ) : isLoading && !isDeleting && scans.length === 0 ? (
          <div className={`p-6 space-y-4 ${isLoading ? 'opacity-50' : 'opacity-100'} transition-opacity`}>
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="animate-pulse flex space-x-4 p-4 border border-line/50 rounded-md bg-surface/50">
                <div className="flex-1 space-y-4 py-1">
                  <div className="h-4 bg-line rounded w-3/4"></div>
                  <div className="space-y-2">
                    <div className="h-4 bg-line rounded w-5/6"></div>
                    <div className="h-4 bg-line rounded w-1/4"></div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : scans.length === 0 ? (
          <div className="p-16 text-center">
            <div className="mx-auto h-12 w-12 text-slate-500 mb-4 flex items-center justify-center rounded-md border border-line bg-surface">
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            {hasFiltersActive ? (
              <>
                <h3 className="text-lg font-medium text-slate-100 mb-2">No scans match your filters.</h3>
                <p className="text-slate-400 mb-6">Clear your filters to see more scans.</p>
                <button
                  onClick={handleReset}
                  className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-accent bg-accent/10 hover:bg-accent/20"
                >
                  Clear Filters
                </button>
              </>
            ) : (
              <>
                <h3 className="text-lg font-medium text-slate-100 mb-2">No scans yet</h3>
                <p className="text-slate-400 mb-6">Run your first URL or email scan to see it appear here.</p>
                <div className="flex justify-center space-x-4">
                  <button onClick={() => navigate('/dashboard')} className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-surface bg-accent hover:bg-accent/90">
                    Go to Dashboard
                  </button>
                </div>
              </>
            )}
          </div>
        ) : (
          <div className={`transition-opacity duration-200 ${isLoading ? 'opacity-50 pointer-events-none' : 'opacity-100'}`}>
            {/* Mobile View (Cards) */}
            <div className="block sm:hidden border-t border-line">
              <ul className="divide-y divide-line">
                {scans.map((scan) => (
                  <li key={scan.id} className="p-4 hover:bg-surface/50 flex flex-col space-y-3 transition-colors">
                    <div className="flex justify-between items-start">
                      <span className="text-sm font-semibold text-slate-200">
                        {scan.scanType || scan.type?.toUpperCase()}
                      </span>
                      <VerdictBadge verdict={scan.verdict || scan.classification?.toUpperCase()} />
                    </div>
                    <div className="text-sm text-slate-400 break-all font-mono bg-surface p-2 rounded border border-line" title={scan.input}>
                      {truncateString(scan.input, 80)}
                    </div>
                    <div className="flex justify-between items-end mt-2">
                      <div className="text-xs text-slate-500 space-y-1">
                        <div>
                          <span className="font-medium text-slate-400">Score:</span> {scan.riskScore !== undefined && scan.riskScore !== null ? `${scan.riskScore}/100` : '-'}
                        </div>
                        <div>
                          <span className="font-medium text-slate-400">Conf:</span> {scan.confidence !== undefined && scan.confidence !== null ? `${Math.round(scan.confidence * 100)}%` : '-'}
                        </div>
                        <div>
                          {formatDate(scan.createdAt)}
                        </div>
                      </div>
                      <div className="space-x-4">
                        <button
                          onClick={() => setScanToDelete(scan.id)}
                          className="text-rose-500 hover:text-rose-400 text-sm font-medium"
                        >
                          Delete
                        </button>
                        <button
                          onClick={() => navigate(`/history/${scan.id}`)}
                          className="text-accent hover:text-accent/80 text-sm font-medium"
                        >
                          View &rarr;
                        </button>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>

            {/* Desktop View (Table) */}
            <div className="hidden sm:block overflow-x-auto">
              <table className="min-w-full divide-y divide-line">
                <thead className="bg-[#091626]">
                  <tr>
                    <th scope="col" className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Type
                    </th>
                    <th scope="col" className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Input
                    </th>
                    <th scope="col" className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Verdict
                    </th>
                    <th scope="col" className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Score
                    </th>
                    <th scope="col" className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Confidence
                    </th>
                    <th scope="col" className="px-6 py-4 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Date
                    </th>
                    <th scope="col" className="relative px-6 py-4">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-panel divide-y divide-line">
                  {scans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-surface/50 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-200 font-semibold">
                        {scan.scanType || scan.type?.toUpperCase()}
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-400 max-w-xs xl:max-w-md truncate font-mono" title={scan.input}>
                        {truncateString(scan.input, 60)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <VerdictBadge verdict={scan.verdict || scan.classification?.toUpperCase()} />
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                        {scan.riskScore !== undefined && scan.riskScore !== null ? (
                          <span className="text-slate-300">{scan.riskScore} <span className="text-slate-500">/ 100</span></span>
                        ) : '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                        {scan.confidence !== undefined && scan.confidence !== null ? `${Math.round(scan.confidence * 100)}%` : '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                        {formatDate(scan.createdAt)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-4">
                        <button
                          onClick={() => setScanToDelete(scan.id)}
                          className="text-rose-500 hover:text-rose-400 transition-colors"
                        >
                          Delete
                        </button>
                        <button
                          onClick={() => navigate(`/history/${scan.id}`)}
                          className="text-accent hover:text-accent/80 transition-colors"
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Pagination */}
        {scans.length > 0 && pagination && (
          <div className="bg-[#091626] px-4 py-3 border-t border-line sm:px-6 flex items-center justify-between">
            <div className="flex-1 flex justify-between sm:hidden">
              <button
                onClick={() => handlePageChange(pagination.page - 1)}
                disabled={pagination.page <= 1}
                className={`relative inline-flex items-center px-4 py-2 border border-line text-sm font-medium rounded-md ${pagination.page <= 1 ? 'bg-surface text-slate-600 cursor-not-allowed' : 'bg-panel text-slate-200 hover:bg-surface'}`}
              >
                Previous
              </button>
              <button
                onClick={() => handlePageChange(pagination.page + 1)}
                disabled={pagination.page >= pagination.totalPages}
                className={`ml-3 relative inline-flex items-center px-4 py-2 border border-line text-sm font-medium rounded-md ${pagination.page >= pagination.totalPages ? 'bg-surface text-slate-600 cursor-not-allowed' : 'bg-panel text-slate-200 hover:bg-surface'}`}
              >
                Next
              </button>
            </div>
            <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
              <div>
                <p className="text-sm text-slate-400">
                  Showing page <span className="font-medium text-slate-200">{pagination.page}</span> of{' '}
                  <span className="font-medium text-slate-200">{pagination.totalPages}</span>
                  {' '}— Total scans: <span className="font-medium text-slate-200">{pagination.total}</span>
                </p>
              </div>
              <div>
                <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
                  <button
                    onClick={() => handlePageChange(pagination.page - 1)}
                    disabled={!pagination.hasPreviousPage && pagination.page <= 1}
                    className={`relative inline-flex items-center px-2 py-2 rounded-l-md border border-line bg-panel text-sm font-medium ${!pagination.hasPreviousPage && pagination.page <= 1 ? 'text-slate-600 cursor-not-allowed' : 'text-slate-300 hover:bg-surface'}`}
                  >
                    <span className="sr-only">Previous</span>
                    <svg className="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                      <path fillRule="evenodd" d="M12.707 5.293a1 1 0 010 1.414L9.414 10l3.293 3.293a1 1 0 01-1.414 1.414l-4-4a1 1 0 010-1.414l4-4a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  </button>
                  <span className="relative inline-flex items-center px-4 py-2 border border-line bg-[#091626] text-sm font-medium text-slate-200">
                    {pagination.page}
                  </span>
                  <button
                    onClick={() => handlePageChange(pagination.page + 1)}
                    disabled={!pagination.hasNextPage && pagination.page >= pagination.totalPages}
                    className={`relative inline-flex items-center px-2 py-2 rounded-r-md border border-line bg-panel text-sm font-medium ${!pagination.hasNextPage && pagination.page >= pagination.totalPages ? 'text-slate-600 cursor-not-allowed' : 'text-slate-300 hover:bg-surface'}`}
                  >
                    <span className="sr-only">Next</span>
                    <svg className="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                      <path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" />
                    </svg>
                  </button>
                </nav>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
