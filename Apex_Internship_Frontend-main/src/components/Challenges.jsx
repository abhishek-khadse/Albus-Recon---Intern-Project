import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  Flag, 
  Terminal, 
  Shield, 
  Globe, 
  Lock, 
  CheckCircle2, 
  Play, 
  Cpu,
  Hash,
  Zap,
  Trophy,
  Clock
} from 'lucide-react';

// --- ANIMATION VARIANTS ---
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.1, delayChildren: 0.1 }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { type: "spring", stiffness: 50, damping: 20 } 
  }
};

const Challenges = () => {
  const [activeFilter, setActiveFilter] = useState('All');

  const categories = ['All', 'Web Security', 'Cryptography', 'System Security', 'Forensics'];

  // Mock Data
  const challenges = [
    { id: 1, title: "SQL Injection Basics", category: "Web Security", points: 100, difficulty: "Easy", status: "Solved", time: "30m", icon: <Globe size={18} /> },
    { id: 2, title: "Crack the Hash", category: "Cryptography", points: 200, difficulty: "Medium", status: "Active", time: "1h", icon: <Hash size={18} /> },
    { id: 3, title: "Linux Privilege Escalation", category: "System Security", points: 300, difficulty: "Hard", status: "Locked", time: "2h", icon: <Terminal size={18} /> },
    { id: 4, title: "XSS Domination", category: "Web Security", points: 150, difficulty: "Medium", status: "Active", time: "45m", icon: <Globe size={18} /> },
    { id: 5, title: "Buffer Overflow 101", category: "System Security", points: 250, difficulty: "Hard", status: "Locked", time: "3h", icon: <Cpu size={18} /> },
    { id: 6, title: "Packet Analysis", category: "Forensics", points: 100, difficulty: "Easy", status: "Active", time: "30m", icon: <Shield size={18} /> },
  ];

  const filteredChallenges = activeFilter === 'All' 
    ? challenges 
    : challenges.filter(c => c.category === activeFilter);

  return (
    <motion.div 
      className="space-y-8 pt-6 md:pt-10"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      
      {/* --- 1. HEADER & STATS --- */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-slate-200 pb-6">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-slate-900">Challenge Lab</h1>
          <p className="text-slate-500 mt-2 max-w-2xl">
            Hands-on cybersecurity labs. Complete missions to earn XP and badges.
          </p>
        </div>
        <div className="flex gap-4">
            {/* Stat Pill 1 */}
            <div className="px-4 py-2 rounded-xl border border-slate-200 bg-white flex items-center gap-3 shadow-sm">
                <div className="p-1.5 bg-indigo-50 text-indigo-600 rounded-lg">
                    <Flag size={18} />
                </div>
                <div>
                    <p className="text-[10px] font-bold text-slate-400 uppercase">CTF Score</p>
                    <p className="text-lg font-black text-slate-900 leading-none">1,250</p>
                </div>
            </div>
            {/* Stat Pill 2 */}
            <div className="px-4 py-2 rounded-xl border border-slate-200 bg-white flex items-center gap-3 shadow-sm">
                <div className="p-1.5 bg-emerald-50 text-emerald-600 rounded-lg">
                    <Trophy size={18} />
                </div>
                <div>
                    <p className="text-[10px] font-bold text-slate-400 uppercase">Rank</p>
                    <p className="text-lg font-black text-slate-900 leading-none">#12</p>
                </div>
            </div>
        </div>
      </div>

      {/* --- 2. FEATURED MISSION (Professional Dark Card) --- */}
      <motion.div variants={itemVariants}>
        <div className="bg-slate-900 rounded-2xl p-1 relative overflow-hidden shadow-xl group">
            {/* Abstract Background */}
            <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-600 rounded-full blur-[100px] opacity-20 -translate-y-1/2 translate-x-1/3"></div>
            
            <div className="bg-slate-900/90 backdrop-blur-md rounded-xl p-8 border border-white/10 relative z-10 flex flex-col md:flex-row items-center justify-between gap-8">
                
                {/* Left Content */}
                <div className="space-y-4 flex-1">
                    <div className="flex items-center gap-3">
                        <span className="px-3 py-1 rounded-full text-[10px] font-bold bg-indigo-500 text-white border border-indigo-400 flex items-center gap-1.5 shadow-[0_0_15px_rgba(99,102,241,0.4)]">
                            <Zap size={12} fill="currentColor" /> Spotlight Mission
                        </span>
                        <span className="text-xs font-medium text-slate-400 flex items-center gap-1">
                            <Clock size={12} /> Est. Time: 2 Hours
                        </span>
                    </div>
                    
                    <div>
                        <h2 className="text-2xl md:text-3xl font-bold text-white mb-2">Metasploit Framework: Zero to Hero</h2>
                        <p className="text-slate-400 text-sm leading-relaxed max-w-xl">
                            Master the industry-standard penetration testing framework. In this lab, you will configure listeners, generate payloads, and exploit a vulnerable Windows machine.
                        </p>
                    </div>

                    <div className="flex items-center gap-4 pt-2">
                        <button className="px-6 py-3 bg-white text-slate-900 hover:bg-indigo-50 rounded-lg font-bold text-sm flex items-center gap-2 transition-all shadow-lg">
                            Start Mission <Play size={16} fill="currentColor" />
                        </button>
                        <span className="text-sm font-bold text-indigo-300">+500 XP Reward</span>
                    </div>
                </div>

                {/* Right Visual */}
                <div className="hidden md:flex items-center justify-center shrink-0">
                    <div className="w-24 h-24 bg-slate-800/50 rounded-2xl border border-white/10 flex items-center justify-center rotate-3 group-hover:rotate-6 transition-transform duration-500">
                        <Terminal size={48} className="text-indigo-400" />
                    </div>
                </div>
            </div>
        </div>
      </motion.div>

      {/* --- 3. MAIN LIST --- */}
      <div className="space-y-6">
        
        {/* Professional Tab Filter */}
        <div className="border-b border-slate-200">
            <div className="flex gap-6 overflow-x-auto no-scrollbar">
                {categories.map((category) => (
                    <button
                        key={category}
                        onClick={() => setActiveFilter(category)}
                        className={`pb-3 text-sm font-bold whitespace-nowrap transition-all relative ${
                            activeFilter === category 
                            ? 'text-indigo-600' 
                            : 'text-slate-500 hover:text-slate-800'
                        }`}
                    >
                        {category}
                        {activeFilter === category && (
                            <motion.div 
                                layoutId="activeTab"
                                className="absolute bottom-0 left-0 w-full h-0.5 bg-indigo-600"
                            />
                        )}
                    </button>
                ))}
            </div>
        </div>

        {/* Challenge Grid */}
        <motion.div 
            className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6"
            variants={containerVariants}
        >
            {filteredChallenges.map((challenge) => (
                <ChallengeCard key={challenge.id} {...challenge} />
            ))}
        </motion.div>

      </div>

    </motion.div>
  );
};

/* --- SUB-COMPONENTS --- */

const ChallengeCard = ({ title, category, points, difficulty, status, time, icon }) => {
    // Styles Configuration
    const isLocked = status === "Locked";
    const isSolved = status === "Solved";

    const difficultyColor = {
        Easy: "bg-emerald-50 text-emerald-700 border-emerald-100",
        Medium: "bg-amber-50 text-amber-700 border-amber-100",
        Hard: "bg-rose-50 text-rose-700 border-rose-100"
    };

    return (
        <motion.div 
            variants={itemVariants}
            whileHover={!isLocked ? { y: -5 } : {}}
            className={`bg-white border rounded-xl p-5 shadow-sm flex flex-col justify-between h-full transition-all relative group ${
                isLocked ? 'border-slate-100 opacity-60' : 'border-slate-200 hover:border-indigo-200 hover:shadow-md'
            }`}
        >
            {/* Header */}
            <div>
                <div className="flex justify-between items-start mb-4">
                    <div className={`p-2 rounded-lg ${isLocked ? 'bg-slate-100 text-slate-400' : 'bg-indigo-50 text-indigo-600'}`}>
                        {icon}
                    </div>
                    {isSolved ? (
                         <span className="flex items-center gap-1 text-[10px] font-bold bg-emerald-100 text-emerald-700 px-2 py-1 rounded-full">
                            <CheckCircle2 size={12} /> Solved
                         </span>
                    ) : (
                        <span className="text-sm font-black text-slate-300 group-hover:text-indigo-100 transition-colors">
                            {points} XP
                        </span>
                    )}
                </div>
                
                <div className="mb-1 flex items-center justify-between">
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{category}</span>
                    <span className="text-[10px] font-medium text-slate-400 flex items-center gap-1">
                         <Clock size={10} /> {time}
                    </span>
                </div>
                <h3 className="text-base font-bold text-slate-900 mb-4 leading-tight group-hover:text-indigo-700 transition-colors">
                    {title}
                </h3>
            </div>

            {/* Footer Actions */}
            <div className="flex items-center justify-between pt-4 border-t border-slate-100">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${difficultyColor[difficulty]}`}>
                    {difficulty}
                </span>

                {isLocked ? (
                    <button className="p-2 rounded-lg bg-slate-50 text-slate-400 border border-slate-100 cursor-not-allowed">
                        <Lock size={16} />
                    </button>
                ) : (
                    <button className="flex items-center gap-1 text-xs font-bold text-slate-900 hover:text-indigo-600 transition-colors">
                        View Lab <Play size={12} fill="currentColor" />
                    </button>
                )}
            </div>
        </motion.div>
    );
};

export default Challenges;