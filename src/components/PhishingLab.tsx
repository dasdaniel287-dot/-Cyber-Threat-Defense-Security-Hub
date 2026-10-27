import React, { useState } from 'react';
import { 
  FishOff, 
  ShieldAlert, 
  ShieldCheck, 
  Award, 
  RotateCcw, 
  ArrowRight, 
  ExternalLink, 
  AlertTriangle, 
  CheckCircle2, 
  Info,
  Mail,
  UserCheck
} from 'lucide-react';
import { PHISHING_QUESTIONS } from '../data/mockSecurityData';

interface PhishingLabProps {
  onScoreUpdate: (score: number, total: number) => void;
}

export const PhishingLab: React.FC<PhishingLabProps> = ({ onScoreUpdate }) => {
  const [currentIdx, setCurrentIdx] = useState<number>(0);
  const [userScore, setUserScore] = useState<number>(0);
  const [answeredState, setAnsweredState] = useState<{
    answered: boolean;
    userChoice: boolean | null;
    isCorrect: boolean | null;
  }>({ answered: false, userChoice: null, isCorrect: null });

  const question = PHISHING_QUESTIONS[currentIdx];
  const isCompleted = currentIdx >= PHISHING_QUESTIONS.length;

  const handleAnswer = (userThinksPhishing: boolean) => {
    if (answeredState.answered || !question) return;

    const isCorrect = userThinksPhishing === question.isPhishing;
    const newScore = isCorrect ? userScore + 1 : userScore;

    setUserScore(newScore);
    setAnsweredState({
      answered: true,
      userChoice: userThinksPhishing,
      isCorrect
    });

    onScoreUpdate(newScore, PHISHING_QUESTIONS.length);
  };

  const handleNext = () => {
    const nextIdx = currentIdx + 1;
    setCurrentIdx(nextIdx);
    setAnsweredState({ answered: false, userChoice: null, isCorrect: null });
  };

  const handleReset = () => {
    setCurrentIdx(0);
    setUserScore(0);
    setAnsweredState({ answered: false, userChoice: null, isCorrect: null });
    onScoreUpdate(0, PHISHING_QUESTIONS.length);
  };

  const getIQRating = () => {
    const percent = (userScore / PHISHING_QUESTIONS.length) * 100;
    if (percent >= 85) return { title: 'Elite SOC Cyber Analyst', color: 'text-[#00ff88]', badge: 'A+' };
    if (percent >= 65) return { title: 'Security-Aware Professional', color: 'text-cyan-400', badge: 'B' };
    if (percent >= 50) return { title: 'Moderate Susceptibility', color: 'text-[#ffb700]', badge: 'C' };
    return { title: 'High Social Engineering Risk', color: 'text-[#ff0055]', badge: 'F' };
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#111625] rounded-2xl border border-slate-800 p-6 sm:p-8 shadow-xl">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div>
            <div className="flex items-center space-x-2 text-[#a855f7] text-xs font-mono uppercase tracking-wider mb-1">
              <FishOff className="w-4 h-4" />
              <span>Interactive Human Firewall Training</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              Phishing & Social Engineering Simulator
            </h2>
            <p className="text-slate-400 text-xs sm:text-sm mt-1 max-w-2xl leading-relaxed">
              Analyze headers, lookalike typosquatting domains, deceptive anchor links, and psychological urgency triggers across realistic attack scenarios.
            </p>
          </div>

          <div className="bg-slate-900 px-4 py-2.5 rounded-xl border border-slate-800 text-center font-mono self-start sm:self-auto shadow-inner">
            <span className="text-[10px] text-slate-400 uppercase block">Training Score</span>
            <span className="text-xl font-bold text-cyan-400">
              {userScore} / {PHISHING_QUESTIONS.length}
            </span>
          </div>
        </div>

        {/* Completion View */}
        {isCompleted ? (
          <div className="mt-8 text-center py-12 px-6 bg-slate-900/60 rounded-2xl border border-slate-800 space-y-5 max-w-xl mx-auto shadow-2xl">
            <div className="w-16 h-16 rounded-full bg-cyan-400/10 text-cyan-400 flex items-center justify-center mx-auto">
              <Award className="w-10 h-10" />
            </div>

            <div className="space-y-2">
              <h3 className="text-2xl font-bold text-white">Phishing Lab Evaluation Completed!</h3>
              <p className="text-slate-400 text-sm">
                You assessed all {PHISHING_QUESTIONS.length} threat and legitimate communication scenarios.
              </p>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono space-y-1">
              <span className="text-xs text-slate-500 uppercase">Assigned Security Rating</span>
              <div className={`text-xl font-bold ${getIQRating().color}`}>
                {getIQRating().title} (Grade: {getIQRating().badge})
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Accuracy: {Math.round((userScore / PHISHING_QUESTIONS.length) * 100)}% ({userScore} of {PHISHING_QUESTIONS.length} correct)
              </p>
            </div>

            <button
              onClick={handleReset}
              className="px-6 py-3 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded-xl text-sm transition-all flex items-center justify-center space-x-2 mx-auto shadow-lg shadow-cyan-500/20"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Retake Training Lab</span>
            </button>
          </div>
        ) : (
          /* Active Question Scenario */
          <div className="mt-8 space-y-6">
            <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-6 space-y-5 font-mono shadow-inner">
              {/* Scenario Header */}
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 border-b border-slate-800 pb-3 text-xs">
                <span className="text-cyan-400 font-bold flex items-center space-x-1.5">
                  <Mail className="w-4 h-4" />
                  <span>Scenario #{currentIdx + 1} of {PHISHING_QUESTIONS.length}: {question.title}</span>
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  question.difficulty === 'HARD'
                    ? 'border-[#ff0055]/30 text-[#ff0055] bg-[#ff0055]/10'
                    : question.difficulty === 'MEDIUM'
                    ? 'border-[#ffb700]/30 text-[#ffb700] bg-[#ffb700]/10'
                    : 'border-[#00ff88]/30 text-[#00ff88] bg-[#00ff88]/10'
                }`}>
                  {question.difficulty} DIFFICULTY
                </span>
              </div>

              {/* Email Client Header Metadata */}
              <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                  <div>
                    <span className="text-slate-500">From: </span>
                    <span className="text-white font-semibold">{question.senderName} </span>
                    <span className="text-amber-400">&lt;{question.senderEmail}&gt;</span>
                  </div>
                  <span className="text-slate-500 text-[11px]">{question.date}</span>
                </div>
                <div>
                  <span className="text-slate-500">To: </span>
                  <span className="text-slate-300">{question.recipient}</span>
                </div>
                <div>
                  <span className="text-slate-500">Subject: </span>
                  <span className="text-white font-bold">{question.subject}</span>
                </div>
              </div>

              {/* Email Body Simulation */}
              <div className="p-5 bg-slate-950 rounded-xl border border-slate-800/80 text-xs sm:text-sm text-slate-200 leading-relaxed space-y-4">
                <div className="whitespace-pre-line font-sans">
                  {question.body}
                </div>

                {/* Simulated Anchor Link with Inspectable Target */}
                {question.linkText && (
                  <div className="pt-2">
                    <div className="group relative inline-block">
                      <div className="px-4 py-2.5 bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-blue-300 rounded-lg text-xs font-semibold flex items-center space-x-2 cursor-pointer transition-all">
                        <span>{question.linkText}</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </div>

                      {/* Hover Tooltip revealing actual destination URL */}
                      <div className="opacity-0 group-hover:opacity-100 transition-opacity absolute bottom-full left-0 mb-2 p-2.5 bg-slate-900 border border-slate-700 text-[11px] text-slate-300 rounded-lg shadow-2xl pointer-events-none whitespace-nowrap z-20 font-mono">
                        <span className="text-slate-500 block text-[10px]">INSPECTED HYPERLINK DESTINATION:</span>
                        <span className="text-cyan-300 font-bold">{question.actualDestination}</span>
                      </div>
                    </div>
                    <span className="text-[11px] text-slate-500 block mt-1 font-mono italic">
                      * Hover over the action button to inspect true destination URL
                    </span>
                  </div>
                )}
              </div>

              {/* Action Buttons: Phishing vs Legitimate */}
              <div className="pt-2">
                <span className="text-xs text-slate-400 block mb-2 font-mono">
                  DECIDE YOUR POSTURE FOR THIS COMMUNICATION:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <button
                    disabled={answeredState.answered}
                    onClick={() => handleAnswer(true)}
                    className="py-3.5 px-4 bg-[#ff0055]/10 hover:bg-[#ff0055]/20 disabled:opacity-50 border border-[#ff0055]/40 text-[#ff0055] font-bold rounded-xl text-xs sm:text-sm transition-all flex items-center justify-center space-x-2 cursor-pointer shadow-sm active:scale-98"
                  >
                    <ShieldAlert className="w-4 h-4" />
                    <span>Flag as Phishing Scam</span>
                  </button>

                  <button
                    disabled={answeredState.answered}
                    onClick={() => handleAnswer(false)}
                    className="py-3.5 px-4 bg-[#00ff88]/10 hover:bg-[#00ff88]/20 disabled:opacity-50 border border-[#00ff88]/40 text-[#00ff88] font-bold rounded-xl text-xs sm:text-sm transition-all flex items-center justify-center space-x-2 cursor-pointer shadow-sm active:scale-98"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    <span>Legitimate Authentic Email</span>
                  </button>
                </div>
              </div>

              {/* Post-Assessment Breakdown & Explanations */}
              {answeredState.answered && (
                <div className={`p-5 rounded-xl border text-xs space-y-3 mt-4 transition-all ${
                  answeredState.isCorrect
                    ? 'bg-[#00ff88]/10 border-[#00ff88]/40 text-[#00ff88]'
                    : 'bg-[#ff0055]/10 border-[#ff0055]/40 text-[#ff0055]'
                }`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 font-bold text-sm">
                      {answeredState.isCorrect ? (
                        <>
                          <CheckCircle2 className="w-5 h-5" />
                          <span>Accurate Assessment! (+1 Score)</span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="w-5 h-5" />
                          <span>Assessment Incorrect!</span>
                        </>
                      )}
                    </div>

                    <button
                      onClick={handleNext}
                      className="px-4 py-2 bg-slate-900 border border-slate-700 hover:border-cyan-400 text-white font-bold rounded-lg text-xs flex items-center space-x-1.5 transition-all shadow-md"
                    >
                      <span>Next Scenario</span>
                      <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
                    </button>
                  </div>

                  <p className="text-slate-200 leading-relaxed font-sans text-xs sm:text-sm">
                    {question.explanation}
                  </p>

                  {/* Bullet Points of Red Flags / Indicators */}
                  {question.redFlags && question.redFlags.length > 0 && (
                    <div className="pt-2 border-t border-slate-800/80 space-y-1 text-slate-300">
                      <span className="text-[#ff0055] font-bold block mb-1">IDENTIFIED RED FLAGS:</span>
                      {question.redFlags.map((flag, idx) => (
                        <div key={idx} className="flex items-start space-x-2 text-[11px]">
                          <span className="text-[#ff0055]">&bull;</span>
                          <span>{flag}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {question.legitIndicators && question.legitIndicators.length > 0 && (
                    <div className="pt-2 border-t border-slate-800/80 space-y-1 text-slate-300">
                      <span className="text-[#00ff88] font-bold block mb-1">LEGITIMATE INDICATORS:</span>
                      {question.legitIndicators.map((ind, idx) => (
                        <div key={idx} className="flex items-start space-x-2 text-[11px]">
                          <span className="text-[#00ff88]">&bull;</span>
                          <span>{ind}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
