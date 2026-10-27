import React, { useState } from 'react';
import { 
  ShieldCheck, 
  LayoutDashboard, 
  Radar, 
  KeyRound, 
  Wifi, 
  FishOff, 
  BookOpen, 
  FileText, 
  Github, 
  Menu, 
  X,
  Bug,
  Cpu
} from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
  onOpenReport: () => void;
  onOpenGithub: () => void;
  threatScore?: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onTabChange,
  onOpenReport,
  onOpenGithub
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scanner', label: 'Threat Scanner', icon: Radar },
    { id: 'deep-lab', label: 'Systems Lab', icon: Cpu },
    { id: 'password', label: 'Password & Breach', icon: KeyRound },
    { id: 'network', label: 'Network Audit', icon: Wifi },
    { id: 'phishing', label: 'Phishing Lab', icon: FishOff },
    { id: 'cve', label: 'CVE Intel', icon: Bug },
    { id: 'tips', label: 'Defense Vault', icon: BookOpen }
  ];

  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div 
            onClick={() => onTabChange('dashboard')}
            className="flex items-center space-x-3 cursor-pointer group"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#7000ff] via-[#00f0ff] to-cyan-300 flex items-center justify-center text-slate-950 font-bold shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition-transform">
              <ShieldCheck className="w-6 h-6 stroke-[2.5]" />
            </div>
            <div>
              <div className="flex items-center">
                <span className="text-xl font-extrabold bg-gradient-to-r from-white via-slate-100 to-[#00f0ff] bg-clip-text text-transparent tracking-tight">
                  AegisShield
                </span>
                <span className="hidden sm:inline-block text-[10px] px-2 py-0.5 rounded-full bg-cyan-400/10 text-cyan-400 border border-cyan-400/30 ml-2 font-mono font-semibold">
                  v3.4 SECURE
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-mono hidden md:block">
                Cyber Threat Defense & Security Operations
              </p>
            </div>
          </div>

          {/* Desktop Navigation Links */}
          <nav className="hidden xl:flex items-center space-x-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`px-3 py-2 rounded-lg text-xs font-medium transition-all flex items-center space-x-1.5 ${
                    isActive
                      ? 'text-[#00f0ff] bg-cyan-950/40 border border-cyan-400/30 shadow-sm shadow-cyan-500/10'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Quick Action Buttons & Status */}
          <div className="flex items-center space-x-2 sm:space-x-3">
            {/* Realtime Status Indicator */}
            <div className="hidden lg:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-slate-900/90 border border-slate-800 text-xs font-mono">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00ff88] opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#00ff88]"></span>
              </span>
              <span className="text-slate-300">Shield: <strong className="text-[#00ff88]">ACTIVE</strong></span>
            </div>

            {/* Export Report Button */}
            <button
              onClick={onOpenReport}
              title="Generate Executive Audit Report"
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 border border-slate-700 hover:border-cyan-400/50 text-slate-300 hover:text-cyan-300 transition-all flex items-center space-x-1.5"
            >
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
              <span className="hidden sm:inline">Audit Report</span>
            </button>

            {/* GitHub Project Info Button */}
            <button
              onClick={onOpenGithub}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-400/40 text-cyan-300 transition-all flex items-center space-x-1.5 shadow-sm shadow-cyan-500/10"
            >
              <Github className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">GitHub Project</span>
            </button>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="xl:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation Dropdown */}
        {mobileMenuOpen && (
          <div className="xl:hidden py-3 border-t border-slate-800 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    onTabChange(item.id);
                    setMobileMenuOpen(false);
                  }}
                  className={`w-full px-3 py-2 rounded-lg text-sm font-medium transition-all flex items-center space-x-2.5 ${
                    isActive
                      ? 'text-[#00f0ff] bg-cyan-950/50 border border-cyan-400/30'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </header>
  );
};
