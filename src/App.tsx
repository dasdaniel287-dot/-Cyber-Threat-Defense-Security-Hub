import React, { useState } from 'react';
import { Header } from './components/Header';
import { Dashboard } from './components/Dashboard';
import { ThreatScanner } from './components/ThreatScanner';
import { PasswordBreachLab } from './components/PasswordBreachLab';
import { NetworkAudit } from './components/NetworkAudit';
import { PhishingLab } from './components/PhishingLab';
import { DefenseVault } from './components/DefenseVault';
import { CveExplorer } from './components/CveExplorer';
import { ReportModal } from './components/ReportModal';
import { GitHubProjectModal } from './components/GitHubProjectModal';
import { INITIAL_THREAT_FEED, PHISHING_QUESTIONS } from './data/mockSecurityData';
import { ThreatFeedItem } from './types/security';
import { Shield, ExternalLink, Github, Heart } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [threatFeed, setThreatFeed] = useState<ThreatFeedItem[]>(INITIAL_THREAT_FEED);
  const [phishingScore, setPhishingScore] = useState<number>(0);
  const [scanCount, setScanCount] = useState<number>(0);
  const [scannerInitialTarget, setScannerInitialTarget] = useState<string>('');

  const [isReportOpen, setIsReportOpen] = useState<boolean>(false);
  const [isGithubOpen, setIsGithubOpen] = useState<boolean>(false);

  const handleRefreshFeed = () => {
    // Shuffle and simulate live feed updates
    setThreatFeed((prev) => {
      const shuffled = [...prev].sort(() => 0.5 - Math.random());
      return shuffled;
    });
  };

  const handleNavigateWithTarget = (tab: string, target?: string) => {
    if (target) {
      setScannerInitialTarget(target);
    }
    setActiveTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handlePhishingScoreUpdate = (score: number) => {
    setPhishingScore(score);
  };

  const handleIncrementScanCount = () => {
    setScanCount((prev) => prev + 1);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0a0d14] text-slate-100 font-sans selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Navigation Header */}
      <Header
        activeTab={activeTab}
        onTabChange={(tab) => {
          setActiveTab(tab);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }}
        onOpenReport={() => setIsReportOpen(true)}
        onOpenGithub={() => setIsGithubOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        {activeTab === 'dashboard' && (
          <Dashboard
            threatFeed={threatFeed}
            onRefreshFeed={handleRefreshFeed}
            onNavigate={handleNavigateWithTarget}
            phishingScore={phishingScore}
            totalPhishingQuestions={PHISHING_QUESTIONS.length}
            scanCount={scanCount}
          />
        )}

        {activeTab === 'scanner' && (
          <ThreatScanner
            initialTarget={scannerInitialTarget}
            onIncrementScanCount={handleIncrementScanCount}
            onBackToDashboard={() => setActiveTab('dashboard')}
          />
        )}

        {activeTab === 'password' && (
          <PasswordBreachLab />
        )}

        {activeTab === 'network' && (
          <NetworkAudit />
        )}

        {activeTab === 'phishing' && (
          <PhishingLab onScoreUpdate={handlePhishingScoreUpdate} />
        )}

        {activeTab === 'cve' && (
          <CveExplorer />
        )}

        {activeTab === 'tips' && (
          <DefenseVault />
        )}
      </main>

      {/* Global Modals */}
      <ReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        phishingScore={phishingScore}
        totalPhishing={PHISHING_QUESTIONS.length}
        scanCount={scanCount}
      />

      <GitHubProjectModal
        isOpen={isGithubOpen}
        onClose={() => setIsGithubOpen(false)}
      />

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-800/80 bg-slate-950/80 py-6 text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row justify-between items-center gap-4">
          <div className="flex items-center space-x-2">
            <div className="w-5 h-5 rounded-md bg-cyan-400/20 text-cyan-400 flex items-center justify-center">
              <Shield className="w-3.5 h-3.5" />
            </div>
            <span className="text-slate-400">
              AegisShield Cyber Threat Defense & Intelligence Hub &copy; {new Date().getFullYear()}. All Rights Reserved.
            </span>
          </div>

          <div className="flex items-center space-x-6">
            <button
              onClick={() => setIsGithubOpen(true)}
              className="hover:text-cyan-400 transition-colors flex items-center space-x-1"
            >
              <Github className="w-3.5 h-3.5" />
              <span>GitHub Repo</span>
            </button>
            <button
              onClick={() => setActiveTab('cve')}
              className="hover:text-cyan-400 transition-colors"
            >
              CVE Advisory Feed
            </button>
            <button
              onClick={() => setActiveTab('tips')}
              className="hover:text-cyan-400 transition-colors"
            >
              Defense Guides
            </button>
            <button
              onClick={() => setIsReportOpen(true)}
              className="hover:text-cyan-400 transition-colors"
            >
              Audit Report
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
