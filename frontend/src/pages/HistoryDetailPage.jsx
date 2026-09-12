import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { scanService } from '../services/scanService';
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
    <span className={`inline-flex items-center px-3 py-1 rounded-md text-sm font-bold border ${colors} uppercase tracking-wide`}>
      {verdict || 'UNKNOWN'}
    </span>
  );
}

function SeverityBadge({ severity }) {
  let colors = 'bg-surface text-slate-300 border-line';
  const s = String(severity || '').toUpperCase();
  if (s === 'CRITICAL') {
    colors = 'bg-rose-900/40 text-rose-300 border-rose-800';
  } else if (s === 'HIGH') {
    colors = 'bg-orange-900/40 text-orange-300 border-orange-800';
  } else if (s === 'MEDIUM') {
    colors = 'bg-amber-900/30 text-amber-300 border-amber-800/50';
  } else if (s === 'LOW') {
    colors = 'bg-blue-900/30 text-blue-300 border-blue-800/50';
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${colors}`}>
      {s || 'INFO'}
    </span>
  );
}

export default function HistoryDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [scan, setScan] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isNotFound, setIsNotFound] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  // AI Explanation State
  const [aiExplanation, setAiExplanation] = useState(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);

  const fetchScanDetails = async () => {
    setIsLoading(true);
    setError(null);
    setIsNotFound(false);

    try {
      const response = await scanService.getScanById(id);
      if (response?.success && response.data) {
        setScan(response.data);
      } else {
        throw new Error('Invalid response structure');
      }
    } catch (err) {
      if (err.response?.status === 404) {
        setIsNotFound(true);
      } else {
        setError(err.response?.data?.error?.message || err.message || 'An error occurred while loading the report.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (id) {
      fetchScanDetails();
    }
  }, [id]);

  const handleDeleteConfirm = async () => {
    setIsDeleting(true);
    try {
      const response = await scanService.deleteScan(id);
      if (response?.success) {
        navigate('/history', { state: { deleted: true } });
      } else {
        throw new Error('Deletion failed without error message');
      }
    } catch (err) {
      setIsDeleting(false);
      setIsDeleteModalOpen(false);
      setError(err.response?.data?.error?.message || err.message || 'An error occurred while deleting the scan.');
    }
  };

  const handleExplainWithAI = async () => {
    setIsAiLoading(true);
    setAiError(null);
    try {
      let response;
      if (scan.scanType === 'URL') {
        response = await scanService.explainUrlWithAI(id);
      } else if (scan.scanType === 'EMAIL') {
        response = await scanService.explainEmailWithAI(id);
      } else {
        throw new Error('Unsupported scan type for AI explanation.');
      }
      
      if (response?.success && response.data) {
        setAiExplanation(response.data);
      } else {
        throw new Error('Invalid AI response structure');
      }
    } catch (err) {
      setAiError(err.response?.data?.error?.message || err.message || 'AI explanation is currently unavailable.');
    } finally {
      setIsAiLoading(false);
    }
  };

  if (isNotFound) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="bg-panel shadow-sm border border-line rounded-lg p-10 text-center">
          <div className="mx-auto h-12 w-12 text-slate-500 mb-4 flex items-center justify-center rounded-md border border-line bg-surface">
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h2 className="text-xl font-bold text-slate-100 mb-2">Scan not found</h2>
          <p className="text-slate-400 mb-6">This scan may no longer exist, or you do not have permission to view it.</p>
          <button
            onClick={() => navigate('/history')}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-surface bg-accent hover:bg-accent/90 transition-colors"
          >
            &larr; Back to History
          </button>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="bg-panel shadow-sm border border-line rounded-lg p-10 text-center">
          <h2 className="text-xl font-bold text-slate-100 mb-2">Unable to load this security report</h2>
          <p className="text-slate-400 mb-6">{error}</p>
          <div className="flex justify-center space-x-4">
            <button
              onClick={() => navigate('/history')}
              className="inline-flex items-center px-4 py-2 border border-line text-sm font-medium rounded-md text-slate-200 bg-surface hover:bg-line transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={fetchScanDetails}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-surface bg-accent hover:bg-accent/90 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (isLoading || !scan) {
    return (
      <div className="max-w-5xl mx-auto px-6 py-8 animate-pulse space-y-6">
        <div className="h-6 w-32 bg-panel rounded mb-8"></div>
        <div className="h-10 w-1/3 bg-panel rounded mb-2"></div>
        <div className="h-4 w-1/4 bg-panel rounded mb-8"></div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 space-y-6">
            <div className="h-48 bg-panel rounded-lg border border-line"></div>
            <div className="h-64 bg-panel rounded-lg border border-line"></div>
          </div>
          <div className="space-y-6">
            <div className="h-32 bg-panel rounded-lg border border-line"></div>
            <div className="h-48 bg-panel rounded-lg border border-line"></div>
          </div>
        </div>
      </div>
    );
  }

  // Derived properties from the backend API contract
  const typeLabel = scan.scanType || scan.type?.toUpperCase() || 'UNKNOWN';
  const confidencePercent = scan.confidence !== undefined && scan.confidence !== null ? Math.round(scan.confidence * 100) : null;
  const analysis = scan.analysis || scan.detectionResult || {};
  const indicators = scan.indicators || scan.detectionReasons || [];

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-8">
      
      <Modal
        isOpen={isDeleteModalOpen}
        onClose={() => setIsDeleteModalOpen(false)}
        onConfirm={handleDeleteConfirm}
        title="Delete scan?"
        message="Are you sure you want to permanently delete this scan? This action cannot be undone."
        confirmText="Delete Scan"
        isDestructive={true}
        isLoading={isDeleting}
      />

      {/* Back Navigation */}
      <div className="mb-6 flex justify-between items-center">
        <button
          onClick={() => navigate('/history')}
          className="text-sm font-medium text-accent hover:text-accent/80 flex items-center transition-colors group"
        >
          <span className="transform group-hover:-translate-x-1 transition-transform mr-1">&larr;</span> 
          Back to Scan History
        </button>
        <button
          onClick={() => setIsDeleteModalOpen(true)}
          className="text-sm font-medium text-rose-500 hover:text-rose-400 transition-colors"
        >
          Delete Scan
        </button>
      </div>

      {/* Header */}
      <div className="mb-8 flex flex-col sm:flex-row sm:items-end justify-between">
        <div>
          <h1 className="text-3xl font-extrabold text-slate-100">Security Report</h1>
          <p className="mt-2 text-sm text-slate-400">
            Detailed security analysis for this scan.
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex items-center space-x-3">
          <div className="text-sm font-mono text-slate-500 bg-panel px-3 py-1 rounded border border-line">
            ID: {scan.id}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Main Content (Left Column) */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Scan Summary */}
          <section className="bg-panel shadow-sm border border-line rounded-lg overflow-hidden">
            <div className="px-6 py-5 border-b border-line bg-surface/30">
              <div className="flex items-center space-x-3">
                <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-line text-slate-200 uppercase">
                  {typeLabel}
                </span>
                <span className="text-sm text-slate-400">Scanned on {formatDate(scan.createdAt)}</span>
              </div>
            </div>
            <div className="px-6 py-6">
              <div className="text-sm text-slate-400 mb-2">Scanned Input</div>
              <div className="font-mono text-slate-200 bg-surface p-4 rounded border border-line break-all">
                {scan.input || scan.normalizedInput || 'No input provided.'}
              </div>
            </div>
          </section>

          {/* Security Findings */}
          <section className="bg-panel shadow-sm border border-line rounded-lg overflow-hidden">
            <div className="px-6 py-5 border-b border-line bg-surface/30">
              <h3 className="text-lg font-semibold text-slate-100">Security Findings</h3>
            </div>
            <div className="px-6 py-6">
              {scan.explanation && (
                <div className="mb-6 p-4 rounded-md bg-surface border border-line">
                  <h4 className="text-sm font-semibold text-slate-300 mb-2">Analysis Summary</h4>
                  <p className="text-sm text-slate-300 leading-relaxed">{scan.explanation}</p>
                </div>
              )}

              {indicators.length > 0 ? (
                <ul className="space-y-4">
                  {indicators.map((ind, idx) => (
                    <li key={idx} className="p-4 bg-surface rounded-md border border-line flex flex-col sm:flex-row sm:items-start gap-4">
                      <div className="flex-shrink-0 mt-0.5">
                        <SeverityBadge severity={ind.severity} />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-slate-200 capitalize">
                          {ind.type ? ind.type.replace(/_/g, ' ') : 'Finding'}
                        </h4>
                        <p className="mt-1 text-sm text-slate-400">
                          {ind.message || 'No details provided.'}
                        </p>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-center py-6 text-slate-400 text-sm">
                  No explicit security findings or indicators were generated for this scan.
                </div>
              )}
            </div>
          </section>

          {/* URL Specific Analysis */}
          {typeLabel === 'URL' && analysis.url && (
            <section className="bg-panel shadow-sm border border-line rounded-lg overflow-hidden">
              <div className="px-6 py-5 border-b border-line bg-surface/30">
                <h3 className="text-lg font-semibold text-slate-100">URL Architecture</h3>
              </div>
              <div className="px-6 py-6">
                <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-6">
                  {analysis.url.protocol && (
                    <div>
                      <dt className="text-sm font-medium text-slate-500">Protocol</dt>
                      <dd className="mt-1 text-sm text-slate-200 font-mono">{analysis.url.protocol}</dd>
                    </div>
                  )}
                  {analysis.url.hostname && (
                    <div>
                      <dt className="text-sm font-medium text-slate-500">Hostname</dt>
                      <dd className="mt-1 text-sm text-slate-200 font-mono break-all">{analysis.url.hostname}</dd>
                    </div>
                  )}
                  {analysis.url.port && (
                    <div>
                      <dt className="text-sm font-medium text-slate-500">Port</dt>
                      <dd className="mt-1 text-sm text-slate-200 font-mono">{analysis.url.port}</dd>
                    </div>
                  )}
                  {analysis.url.pathname && (
                    <div className="sm:col-span-2">
                      <dt className="text-sm font-medium text-slate-500">Pathname</dt>
                      <dd className="mt-1 text-sm text-slate-200 font-mono break-all">{analysis.url.pathname}</dd>
                    </div>
                  )}
                </dl>
              </div>
            </section>
          )}

          {/* Email Specific Analysis */}
          {typeLabel === 'EMAIL' && (analysis.emailIndicators || analysis.metrics) && (
            <section className="bg-panel shadow-sm border border-line rounded-lg overflow-hidden">
              <div className="px-6 py-5 border-b border-line bg-surface/30">
                <h3 className="text-lg font-semibold text-slate-100">Email Analysis</h3>
              </div>
              <div className="px-6 py-6 space-y-6">
                {scan.metadata?.subjectPreview && (
                  <div>
                    <div className="text-sm font-medium text-slate-500 mb-1">Subject Preview</div>
                    <div className="font-mono text-slate-300 bg-surface p-3 rounded border border-line break-words">
                      {scan.metadata.subjectPreview}
                    </div>
                  </div>
                )}
                
                {analysis.metrics && (
                  <dl className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="bg-surface p-4 rounded border border-line">
                      <dt className="text-xs font-medium text-slate-500 uppercase tracking-wide">URLs Extracted</dt>
                      <dd className="mt-1 text-xl font-semibold text-slate-200">{analysis.metrics.urlsExtracted ?? 0}</dd>
                    </div>
                  </dl>
                )}
        </div>
            </section>
          )}

          {/* AI Security Analysis */}
          {(typeLabel === 'URL' || typeLabel === 'EMAIL') && (
            <section className="bg-panel shadow-sm border border-line rounded-lg overflow-hidden mt-6">
              <div className="px-6 py-5 border-b border-line bg-surface/30 flex items-center justify-between">
                <h3 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                  <svg className="w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                  AI Security Analysis
                </h3>
                {!aiExplanation && !isAiLoading && !aiError && (
                  <button
                    onClick={handleExplainWithAI}
                    className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded text-surface bg-accent hover:bg-accent/90 transition-colors"
                  >
                    AI Security Analysis
                  </button>
                )}
              </div>
              <div className="px-6 py-6">
                {isAiLoading && (
                  <div className="flex items-center gap-3 text-slate-400">
                    <svg className="animate-spin h-5 w-5 text-accent" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Analyzing security indicators...
                  </div>
                )}
                
                {aiError && (
                  <div className="text-slate-400 text-sm p-4 bg-surface rounded border border-line flex flex-col sm:flex-row gap-4 justify-between items-start sm:items-center">
                    <div>
                      <p className="font-semibold text-slate-300 mb-1">AI analysis unavailable.</p>
                      <p className="text-xs">Your security scan is still valid. PhishGuard's detector results remain available above.</p>
                    </div>
                    <button 
                      onClick={handleExplainWithAI}
                      className="text-xs text-accent hover:underline font-medium whitespace-nowrap"
                    >
                      Try again
                    </button>
                  </div>
                )}
                
                {aiExplanation && (
                  <div className="space-y-6">
                    <div>
                      <h4 className="text-sm font-medium text-slate-500 mb-1">Threat Category</h4>
                      <div className="text-lg font-bold text-slate-200">{aiExplanation.threatType}</div>
                    </div>
                    
                    {aiExplanation.socialEngineering && aiExplanation.socialEngineering.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-slate-500 mb-2">Social Engineering Indicators</h4>
                        <ul className="list-disc list-inside space-y-1">
                          {aiExplanation.socialEngineering.map((ind, i) => (
                            <li key={i} className="text-sm text-slate-300">{ind}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    <div>
                      <h4 className="text-sm font-medium text-slate-500 mb-2">Explanation</h4>
                      <p className="text-sm text-slate-300 leading-relaxed bg-surface p-4 rounded border border-line">
                        {aiExplanation.explanation}
                      </p>
                    </div>
                    
                    {aiExplanation.keyIndicators && aiExplanation.keyIndicators.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-slate-500 mb-2">Key Indicators</h4>
                        <ul className="list-disc list-inside space-y-1">
                          {aiExplanation.keyIndicators.map((ind, i) => (
                            <li key={i} className="text-sm text-slate-300">{ind}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    <div>
                      <h4 className="text-sm font-medium text-slate-500 mb-2">Recommended Action</h4>
                      <div className="text-sm text-slate-200 font-medium p-4 bg-accent/10 border border-accent/20 rounded-md">
                        {aiExplanation.recommendation}
                      </div>
                    </div>
                    
                    <div className="pt-2 text-xs text-slate-500 italic border-t border-line">
                      AI-generated explanation based on PhishGuard's detected security indicators.
                    </div>
                  </div>
                )}
                
                {!isAiLoading && !aiError && !aiExplanation && (
                  <p className="text-sm text-slate-400 text-center py-4">
                    Click the button above to generate an AI explanation for this scan.
                  </p>
                )}
              </div>
            </section>
          )}

        </div>

        {/* Sidebar (Right Column) */}
        <div className="space-y-6">
          
          {/* Risk Assessment */}
          <section className="bg-panel shadow-sm border border-line rounded-lg overflow-hidden">
            <div className="px-6 py-5 border-b border-line bg-surface/30">
              <h3 className="text-lg font-semibold text-slate-100">Risk Assessment</h3>
            </div>
            <div className="px-6 py-6 space-y-6">
              
              <div>
                <div className="text-sm font-medium text-slate-500 mb-2">Verdict</div>
                <VerdictBadge verdict={scan.verdict || scan.classification?.toUpperCase()} />
              </div>

              {scan.riskScore !== undefined && scan.riskScore !== null && (
                <div>
                  <div className="flex justify-between items-end mb-1">
                    <span className="text-sm font-medium text-slate-500">Risk Score</span>
                    <span className="text-lg font-bold text-slate-100">{scan.riskScore} <span className="text-sm text-slate-500 font-normal">/ 100</span></span>
                  </div>
                  <div className="w-full bg-surface rounded-full h-2.5 border border-line overflow-hidden">
                    <div 
                      className={`h-2.5 rounded-full ${
                        scan.riskScore >= 60 ? 'bg-rose-500' : scan.riskScore >= 30 ? 'bg-amber-500' : 'bg-emerald-500'
                      }`} 
                      style={{ width: `${Math.min(100, Math.max(0, scan.riskScore))}%` }}
                    ></div>
                  </div>
                </div>
              )}

              {confidencePercent !== null && (
                <div>
                  <div className="flex justify-between items-end mb-1">
                    <span className="text-sm font-medium text-slate-500">Confidence</span>
                    <span className="text-sm font-bold text-slate-200">{confidencePercent}%</span>
                  </div>
                  <div className="w-full bg-surface rounded-full h-1.5 border border-line overflow-hidden">
                    <div 
                      className="bg-accent h-1.5 rounded-full opacity-80" 
                      style={{ width: `${Math.min(100, Math.max(0, confidencePercent))}%` }}
                    ></div>
                  </div>
                </div>
              )}

            </div>
          </section>

          {/* Metadata */}
          <section className="bg-panel shadow-sm border border-line rounded-lg overflow-hidden">
            <div className="px-6 py-5 border-b border-line bg-surface/30">
              <h3 className="text-lg font-semibold text-slate-100">Metadata</h3>
            </div>
            <div className="px-6 py-6">
              <dl className="space-y-4">
                <div>
                  <dt className="text-xs font-medium text-slate-500 uppercase tracking-wide">Status</dt>
                  <dd className="mt-1 text-sm text-slate-300">Completed</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-slate-500 uppercase tracking-wide">Created</dt>
                  <dd className="mt-1 text-sm text-slate-300">{formatDate(scan.createdAt)}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-slate-500 uppercase tracking-wide">Analyzer Engine</dt>
                  <dd className="mt-1 text-sm text-slate-300">v1.0 (Heuristics)</dd>
                </div>
              </dl>
            </div>
          </section>

        </div>
      </div>
    </div>
  );
}
