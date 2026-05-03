import React from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { 
  Shield, Globe, Code, Terminal, Database, Briefcase, 
  CheckCircle2, Lock, ArrowRight, BookOpen, Play, 
  TrendingUp, Clock, ChevronRight
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

const Courses = () => {
  return (
    <motion.div 
      className="space-y-8 pt-6 md:pt-10"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      
      {/* --- HEADER --- */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-slate-200 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="px-2.5 py-1 bg-indigo-50 text-indigo-600 border border-indigo-100 rounded-md text-xs font-bold">
              The ACS Internship
            </span>
            <span className="px-2.5 py-1 bg-emerald-50 text-emerald-600 border border-emerald-100 rounded-md text-xs font-bold flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full"></div>
              Active
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-bold text-slate-900 mb-2">Curriculum & Tracks</h1>
          <p className="text-slate-500 text-sm max-w-2xl">
            Complete fundamentals, choose your specialization, and launch your career.
          </p>
        </div>
      </div>

      {/* --- STAGE 1: FUNDAMENTALS --- */}
      <motion.div variants={itemVariants} className="space-y-4">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-slate-900 text-white text-xs font-bold">1</span>
          <h2 className="text-lg font-bold text-slate-900">Foundation Track</h2>
          <span className="px-2 py-0.5 bg-amber-50 text-amber-700 border border-amber-100 text-[10px] font-bold uppercase rounded">Required</span>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          <CompactCourseCard 
            title="Cyber Security Fundamentals"
            courseId="cyber-security-fundamentals" 
            code="CS-101"
            status="Completed"
            progress={100}
            icon={<Shield size={18} />}
            lessons={24}
            duration="12h"
          />
          <CompactCourseCard 
            title="Networking Essentials"
            courseId="networking-essentials"
            code="NT-102"
            status="In Progress"
            progress={65}
            icon={<Globe size={18} />}
            lessons={28}
            duration="14h"
          />
          <CompactCourseCard 
            title="Programming with Python"
            courseId="programming-with-python"
            code="PY-103"
            status="Locked"
            progress={0}
            icon={<Code size={18} />}
            lessons={32}
            duration="16h"
          />
          <CompactCourseCard 
            title="Linux Fundamentals"
            courseId="linux-fundamentals"
            code="LX-104"
            status="Locked"
            progress={0}
            icon={<Terminal size={18} />}
            lessons={20}
            duration="10h"
          />
        </div>
      </motion.div>

      {/* --- STAGE 2: SPECIALIZATION TRACKS --- */}
      <motion.div variants={itemVariants} className="space-y-4 pt-4">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-indigo-600 text-white text-xs font-bold">2</span>
          <h2 className="text-lg font-bold text-slate-900">Specialization Path</h2>
          <span className="px-2 py-0.5 bg-purple-50 text-purple-700 border border-purple-100 text-[10px] font-bold uppercase rounded">Choose One</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          
          {/* Track A: Web Security */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:shadow-md hover:border-indigo-300 transition-all group flex flex-col h-full">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-indigo-50 rounded-lg group-hover:bg-indigo-100 transition-colors">
                  <Globe size={22} className="text-indigo-600" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-slate-900 group-hover:text-indigo-600 transition-colors">
                    Web Security & VAPT
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">OWASP, Burp Suite, Web Pentesting</p>
                </div>
              </div>
              <span className="px-2 py-0.5 bg-indigo-50 text-indigo-600 border border-indigo-100 text-[10px] font-bold uppercase rounded">
                Track A
              </span>
            </div>

            <div className="space-y-2 mb-4">
              <ModuleItem title="Web Development Fundamentals" />
              <ModuleItem title="Web Security & VAPT" />
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-slate-100 mt-auto">
              <div className="flex items-center gap-4 text-xs text-slate-500">
                <span className="flex items-center gap-1"><BookOpen size={12} /> 2 Modules</span>
                <span className="flex items-center gap-1"><Clock size={12} /> 28h</span>
              </div>
              {/* Ensure this ID matches VALID_TRACK_IDS exactly */}
              <Link to="/track/web-security-track">
                <button className="px-4 py-2 rounded-lg bg-indigo-50 text-indigo-600 hover:bg-indigo-600 hover:text-white border border-indigo-100 hover:border-indigo-600 font-bold text-xs transition-all flex items-center gap-1.5 group-hover:gap-2">
                  View Track <ArrowRight size={14} />
                </button>
              </Link>
            </div>
          </div>

          {/* Track B: Blockchain */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:shadow-md hover:border-purple-300 transition-all group flex flex-col h-full">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-purple-50 rounded-lg group-hover:bg-purple-100 transition-colors">
                  <Database size={22} className="text-purple-600" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-slate-900 group-hover:text-purple-600 transition-colors">
                    Blockchain & Smart Contracts
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">DeFi, Solidity, Contract Auditing</p>
                </div>
              </div>
              <span className="px-2 py-0.5 bg-purple-50 text-purple-600 border border-purple-100 text-[10px] font-bold uppercase rounded">
                Track B
              </span>
            </div>

            <div className="space-y-2 mb-4">
              <ModuleItem title="Blockchain & DeFi Fundamentals" />
              <ModuleItem title="Solidity Development" />
              <ModuleItem title="Smart Contract Security" />
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-slate-100 mt-auto">
              <div className="flex items-center gap-4 text-xs text-slate-500">
                <span className="flex items-center gap-1"><BookOpen size={12} /> 3 Modules</span>
                <span className="flex items-center gap-1"><Clock size={12} /> 36h</span>
              </div>
              {/* Ensure this ID matches VALID_TRACK_IDS exactly */}
              <Link to="/track/blockchain-security-track">
                <button className="px-4 py-2 rounded-lg bg-purple-50 text-purple-600 hover:bg-purple-600 hover:text-white border border-purple-100 hover:border-purple-600 font-bold text-xs transition-all flex items-center gap-1.5 group-hover:gap-2">
                  View Track <ArrowRight size={14} />
                </button>
              </Link>
            </div>
          </div>

        </div>
      </motion.div>

            {/* --- 4. STAGE 3: PROFESSIONAL LAUNCH --- */}
            <motion.div variants={itemVariants} className="space-y-4 pt-4 pb-8">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center w-7 h-7 rounded-lg bg-slate-300 text-slate-600 text-xs font-bold">3</span>
          <h2 className="text-lg font-bold text-slate-900">Career Launch</h2>
          <span className="px-2 py-0.5 bg-slate-100 text-slate-500 border border-slate-200 text-[10px] font-bold uppercase rounded">Final Stage</span>
        </div>

        <div className="bg-slate-50 border border-slate-200 rounded-xl p-5 flex flex-col md:flex-row items-center justify-between gap-4 opacity-75">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-white border border-slate-200 rounded-lg flex items-center justify-center text-slate-400">
              <Briefcase size={22} />
            </div>
            <div>
              <h3 className="font-bold text-slate-700 text-base">Bug Bounty & Career Opportunities</h3>
              <p className="text-xs text-slate-500 mt-0.5">Real-world hunting, reports, and placement support.</p>
            </div>
          </div>
          <div className="flex items-center gap-2 px-3 py-2 bg-white rounded-lg border border-slate-200 text-slate-400 text-xs font-bold uppercase tracking-wide">
            <Lock size={14} />
            Locked
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
};

/* --- FIXED SUB-COMPONENT: CompactCourseCard --- */
// Now accepts an explicit 'courseId' prop so we don't guess the URL from the Title
const CompactCourseCard = ({ title, courseId, code, status, progress, icon, lessons, duration }) => {
  const isLocked = status === 'Locked';
  const isCompleted = status === 'Completed';

  // Fallback generation if courseId isn't passed (safety)
  const safeId = courseId || title.toLowerCase().replace(/ /g, '-').replace(/[^\w-]+/g, '');

  return (
    <div className={`bg-white border rounded-xl p-4 shadow-sm flex flex-col justify-between h-full transition-all ${
      isLocked ? 'border-slate-100 opacity-60' : 'border-slate-200 hover:border-indigo-200 hover:shadow-md'
    }`}>
      {/* (Previous visual code for icon and title remains the same) */}
      <div>
        <div className="flex justify-between items-start mb-3">
          <div className={`p-2 rounded-lg ${isLocked ? 'bg-slate-100 text-slate-400' : isCompleted ? 'bg-emerald-50 text-emerald-600' : 'bg-indigo-50 text-indigo-600'}`}>
            {icon}
          </div>
          {isCompleted && <div className="p-1.5 bg-emerald-50 rounded-md"><CheckCircle2 size={14} className="text-emerald-600" /></div>}
          {isLocked && <div className="p-1.5 bg-slate-100 rounded-md"><Lock size={14} className="text-slate-400" /></div>}
        </div>
        <div className="mb-1"><span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{code}</span></div>
        <h3 className="font-bold text-slate-900 text-sm mb-3 leading-tight min-h-[36px]">{title}</h3>
        <div className="flex items-center gap-3 mb-3 text-xs text-slate-500">
          <span className="flex items-center gap-1"><BookOpen size={11} /><span className="font-semibold">{lessons}</span></span>
          <span className="w-1 h-1 bg-slate-300 rounded-full"></span>
          <span className="flex items-center gap-1"><Play size={11} /><span className="font-semibold">{duration}</span></span>
        </div>
      </div>

      <div className="space-y-2">
        <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden">
          <div className={`h-full rounded-full transition-all duration-500 ${isCompleted ? 'bg-emerald-500' : 'bg-indigo-600'}`} style={{ width: `${progress}%` }}></div>
        </div>
        <div className="flex items-center justify-between">
          <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${isLocked ? 'bg-slate-100 text-slate-400 border border-slate-200' : 'bg-indigo-50 text-indigo-600 border border-indigo-100'}`}>{status}</span>
          {!isLocked && (
            <Link to={`/courses/${safeId}`} className="text-xs font-bold text-slate-600 hover:text-indigo-600 flex items-center gap-1 transition-colors">
              Details <ChevronRight size={12} />
            </Link>
          )}
        </div>
      </div>
    </div>
  );
};

const ModuleItem = ({ title }) => (
  <div className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 border border-slate-100">
    <div className="w-1.5 h-1.5 bg-slate-400 rounded-full"></div>
    <span className="text-xs font-semibold text-slate-700">{title}</span>
  </div>
);

export default Courses;