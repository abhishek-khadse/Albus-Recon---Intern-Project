import React, { useState, useMemo } from 'react';
import { useParams, Link, Navigate } from 'react-router-dom';
import { 
  Play, CheckCircle2, Lock, ChevronDown, ChevronLeft, 
  Clock, Award, BarChart3, Shield, 
  ArrowRight, LayoutDashboard, MonitorPlay, BookOpen,
  GraduationCap, Code2, Target, Sparkles, Zap, TrendingUp,
  Terminal, Database, FileText, Globe, Bug, Briefcase, LockKeyhole
} from 'lucide-react';

import { courseData } from './utils/courseinfo';

// --- ICON MAP CONFIGURATION ---
const IconMap = {
  shield: Shield,
  lock: Lock,
  file: FileText,
  globe: Globe,
  code: Code2,
  terminal: Terminal,
  database: Database,
  bug: Bug,
  "lock-closed": LockKeyhole,
  certificate: Award,
  briefcase: Briefcase
};

// --- Lesson Item ---
const LessonItem = ({ lesson, index, trackId, isLocked, isActive }) => {
  // FIX: Encoding ID for special chars (like '&')
  const safeLessonId = encodeURIComponent(lesson.id);
  const lessonPath = trackId 
    ? `/track/${trackId}/lesson/${safeLessonId}` 
    : `/lesson/${safeLessonId}`;

  return (
    <div className="relative group">
      {isActive && (
        <div className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-blue-500 to-blue-600 rounded-r" />
      )}

      {isLocked ? (
        <div className="flex items-center gap-3 py-3.5 px-4 opacity-40 cursor-not-allowed">
          <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center">
            <Lock size={14} className="text-slate-400" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-slate-600 truncate">{lesson.title}</p>
            <span className="text-xs text-slate-400 mt-0.5 block">{lesson.duration}</span>
          </div>
        </div>
      ) : (
        <Link 
          to={lessonPath}
          className={`w-full flex items-center gap-3 py-3.5 px-4 transition-all ${
            isActive 
              ? 'bg-gradient-to-r from-blue-50 to-transparent' 
              : 'hover:bg-slate-50/80'
          }`}
        >
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all ${
            lesson.completed 
              ? 'bg-gradient-to-br from-green-50 to-green-100 text-green-600 shadow-sm' 
              : isActive 
              ? 'bg-gradient-to-br from-blue-50 to-blue-100 text-blue-600 shadow-sm' 
              : 'bg-slate-100 text-slate-400 group-hover:bg-blue-50 group-hover:text-blue-600'
          }`}>
            {lesson.completed ? <CheckCircle2 size={16} /> : <Play size={16} />}
          </div>
          
          <div className="flex-1 min-w-0 text-left">
            <p className={`text-sm font-medium truncate ${
              isActive ? 'text-slate-900' : 'text-slate-700 group-hover:text-slate-900'
            }`}>
              {lesson.title}
            </p>
            <span className="text-xs text-slate-500 mt-0.5 block">{lesson.duration}</span>
          </div>
          
          {isActive && (
            <div className="flex items-center gap-1">
              <div className="w-1.5 h-1.5 rounded-full bg-blue-600 animate-pulse" />
              <div className="w-1 h-1 rounded-full bg-blue-400 animate-pulse" style={{animationDelay: '0.2s'}} />
            </div>
          )}
        </Link>
      )}
    </div>
  );
};

// --- Module Section ---
const ModuleSection = ({ module, index, trackId, isLocked, isFinalExam }) => {
  const [isOpen, setIsOpen] = useState(index === 0 || !isLocked); 
  const totalLessons = module.lessons.length;
  const completedLessons = module.lessons.filter(l => l.completed).length;
  const isCompleted = totalLessons === completedLessons && totalLessons > 0;
  const progressPercent = totalLessons > 0 ? (completedLessons / totalLessons) * 100 : 0;

  return (
    <div className={`${isLocked ? 'opacity-50' : ''} border-b border-slate-100 last:border-b-0`}>
      <button
        onClick={() => !isLocked && setIsOpen(!isOpen)}
        disabled={isLocked}
        className={`w-full flex items-center justify-between p-4 text-left transition-all ${
          isOpen ? 'bg-slate-50/50' : 'hover:bg-slate-50/50'
        }`}
      >
        <div className="flex items-center gap-3 flex-1 pr-4">
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all ${
            isLocked 
              ? 'bg-slate-100 text-slate-400' 
              : isCompleted 
              ? 'bg-gradient-to-br from-green-50 to-green-100 text-green-600 shadow-sm'
              : 'bg-gradient-to-br from-blue-50 to-blue-100 text-blue-600 shadow-sm'
          }`}>
            {isFinalExam ? (
              <Award size={18} />
            ) : (
              <span className="text-sm font-bold">{index + 1}</span>
            )}
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className={`text-xs font-semibold ${
                isLocked ? 'text-slate-400' : isCompleted ? 'text-green-600' : 'text-blue-600'
              }`}>
                {isFinalExam ? 'Final Assessment' : `Module ${index + 1}`}
              </span>
              {isCompleted && (
                <div className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-green-50">
                  <CheckCircle2 size={12} className="text-green-600" />
                  <span className="text-xs font-medium text-green-700">Complete</span>
                </div>
              )}
            </div>
            <h3 className={`text-sm font-semibold leading-tight ${isLocked ? 'text-slate-400' : 'text-slate-900'}`}>
              {module.title}
            </h3>
            {!isLocked && !isFinalExam && (
              <div className="flex items-center gap-2 mt-2">
                <div className="flex-1 h-1 bg-slate-200 rounded-full overflow-hidden max-w-[120px]">
                  <div 
                    className="h-full bg-gradient-to-r from-blue-500 to-blue-600 rounded-full transition-all duration-500"
                    style={{ width: `${progressPercent}%` }}
                  />
                </div>
                <span className="text-xs text-slate-500 font-medium">
                  {completedLessons}/{totalLessons}
                </span>
              </div>
            )}
          </div>
        </div>
        
        <div className="text-slate-400">
          {isLocked ? (
            <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center">
              <Lock size={14} />
            </div>
          ) : (
            <ChevronDown size={18} className={`transition-transform ${isOpen ? 'rotate-180' : ''}`} />
          )}
        </div>
      </button>

      {isOpen && !isLocked && (
        <div className="bg-white">
          {module.lessons.map((lesson, i) => (
            <LessonItem 
              key={i} 
              lesson={lesson} 
              index={i} 
              trackId={trackId} 
              isLocked={isLocked}
              isActive={i === 0 && index === 0}
            />
          ))}
        </div>
      )}
    </div>
  );
};

const CourseDetail = () => {
  const { id: courseId, trackId } = useParams();
  const course = courseData[courseId];

  // Safety Redirect
  if (!course) {
    return <Navigate to="/courses" replace />;
  }

  const stats = useMemo(() => {
    const allLessons = course.modules.flatMap(m => m.lessons);
    const totalCount = allLessons.length;
    const completedCount = allLessons.filter(l => l.completed).length;
    const percentage = totalCount === 0 ? 0 : Math.round((completedCount / totalCount) * 100);
    return { totalCount, percentage, completedCount }; 
  }, [course]);

  const allModules = [...course.modules, { 
    title: "Certification Exam", 
    lessons: [{ id: 'final-exam', title: 'Final Assessment', duration: '60:00', completed: false }] 
  }];

  const backLink = trackId ? `/track/${trackId}` : "/courses";
  const startLessonId = course.modules[0]?.lessons[0]?.id || 'default';
  const safeStartLessonId = encodeURIComponent(startLessonId);
  const baseLessonPath = trackId ? `/track/${trackId}/lesson` : `/lesson`;
  const linkTarget = `${baseLessonPath}/${safeStartLessonId}`;

  // --- DYNAMIC DATA PREPARATION ---
  
  // 1. Objectives (Fallback to generic if empty)
  const learningObjectives = course.learningObjectives || [
    "Master core security concepts and architecture",
    "Understand theoretical and practical threat models",
    "Apply industry-standard security frameworks",
    "Develop real-world auditing skills"
  ];

  // 2. Prerequisites (Fallback to generic if empty)
  const prerequisites = course.prerequisites || [
    "Basic computer literacy",
    "Understanding of internet fundamentals",
    "No prior cybersecurity experience required"
  ];

  // 3. Stats Data (Dynamic from course object)
  const courseLevel = course.level || "Beginner";
  const courseDuration = course.duration || "Self-Paced";

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-white">
      
      {/* HEADER */}
      <div className="relative bg-white border-b border-slate-200 overflow-hidden">
        {/* Background Effects */}
        <div className="absolute top-0 right-0 w-[800px] h-[800px] bg-gradient-to-br from-blue-50 via-transparent to-transparent opacity-40 blur-3xl" />
        <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-gradient-to-tr from-violet-50 via-transparent to-transparent opacity-30 blur-3xl" />
        <div className="absolute right-0 top-1/2 -translate-y-1/2 opacity-[0.02] pointer-events-none">
          <Shield size={500} className="text-slate-900" />
        </div>

        <div className="max-w-7xl mx-auto px-6 py-8 relative z-10">
          {/* Navigation */}
          <div className="flex items-center justify-between mb-8">
            <Link to={backLink} className="flex items-center gap-2 text-sm text-slate-600 hover:text-slate-900 transition-colors group">
              <div className="w-8 h-8 rounded-lg bg-white border border-slate-200 flex items-center justify-center group-hover:border-slate-300 group-hover:shadow-sm transition-all">
                <ChevronLeft size={16} />
              </div>
              <span className="font-medium">Back to {trackId ? 'Track' : 'Dashboard'}</span>
            </Link>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 px-3 py-1.5 bg-white border border-green-200 rounded-lg text-xs text-green-700 font-medium shadow-sm">
                <Shield size={12} />
                <span>Verified Course</span>
              </div>
            </div>
          </div>

          {/* Title Area */}
          <div className="flex flex-col lg:flex-row justify-between gap-8 pb-8">
            <div className="max-w-3xl">
              
              {/* Dynamic Tags */}
              <div className="flex flex-wrap items-center gap-3 mb-5">
                {course.tags && course.tags.length > 0 ? (
                  course.tags.map((tag, index) => {
                    const IconComponent = IconMap[tag.icon] || Shield;
                    return (
                      <div key={index} className="inline-flex items-center gap-2 px-3.5 py-1.5 bg-gradient-to-r from-blue-50 to-blue-100 text-blue-700 rounded-full text-xs font-semibold border border-blue-200 shadow-sm">
                        <IconComponent size={12} />
                        <span>{tag.label}</span>
                      </div>
                    );
                  })
                ) : (
                  <div className="inline-flex items-center gap-2 px-3.5 py-1.5 bg-gradient-to-r from-blue-50 to-blue-100 text-blue-700 rounded-full text-xs font-semibold border border-blue-200 shadow-sm">
                    <Shield size={12} />
                    <span>Cyber Security</span>
                  </div>
                )}
              </div>

              <h1 className="text-4xl lg:text-5xl font-bold text-slate-900 mb-5 leading-tight">
                {course.title}
              </h1>
              {/* Truncated description for header */}
              <p className="text-lg text-slate-600 leading-relaxed">
                {course.description.substring(0, 276)}{course.description.length > 276 ? "" : ""}
              </p>
            </div>

            {/* Progress Card */}
            <div className="relative bg-white rounded-2xl p-6 min-w-[300px] border border-slate-200 shadow-lg shadow-slate-200/50">
              <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-blue-50 to-transparent opacity-50 rounded-2xl" />
              
              <div className="relative z-10">
                <div className="flex justify-between items-center mb-4">
                  <span className="text-sm font-semibold text-slate-700">Your Progress</span>
                  <div className="px-2.5 py-1 bg-blue-50 rounded-lg">
                    <span className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-blue-700 bg-clip-text text-transparent">{stats.percentage}%</span>
                  </div>
                </div>
                
                <div className="relative w-full h-3 bg-slate-100 rounded-full overflow-hidden mb-6">
                  <div 
                    className="h-full bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 rounded-full transition-all duration-1000 shadow-sm"
                    style={{ width: `${stats.percentage}%` }}
                  />
                </div>
                
                <Link 
                  to={linkTarget} 
                  className="flex items-center justify-center gap-2 w-full py-3.5 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white text-sm font-semibold rounded-xl transition-all shadow-lg shadow-blue-200 hover:shadow-xl hover:shadow-blue-300 group"
                >
                  <span>{stats.percentage > 0 ? 'Continue Learning' : 'Start Course'}</span>
                  <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" />
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* MAIN CONTENT */}
      <div className="max-w-7xl mx-auto px-6 py-12">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* LEFT COLUMN */}
          <div className="lg:col-span-8 space-y-6">
            
            {/* Dynamic Quick Stats */}
            <div className="grid grid-cols-3 gap-4">
              {[
                { 
                  icon: BarChart3, 
                  label: 'Level', 
                  value: courseLevel, 
                  gradient: 'from-purple-50 to-purple-100', 
                  color: 'text-purple-600', 
                  border: 'border-purple-200' 
                },
                { 
                  icon: Clock, 
                  label: 'Duration', 
                  value: courseDuration, 
                  gradient: 'from-blue-50 to-blue-100', 
                  color: 'text-blue-600', 
                  border: 'border-blue-200' 
                },
                { 
                  icon: Award, 
                  label: 'Certificate', 
                  value: 'Included', 
                  gradient: 'from-green-50 to-green-100', 
                  color: 'text-green-600', 
                  border: 'border-green-200' 
                }
              ].map((stat, i) => (
                <div 
                  key={i} 
                  className={`bg-gradient-to-br ${stat.gradient} rounded-xl border ${stat.border} p-5 hover:shadow-md transition-all group`}
                >
                  <stat.icon size={22} className={`${stat.color} mb-3 group-hover:scale-110 transition-transform`} />
                  <p className="text-xs text-slate-600 font-medium mb-1">{stat.label}</p>
                  <p className={`text-sm font-bold ${stat.color} line-clamp-1`} title={stat.value}>{stat.value}</p>
                </div>
              ))}
            </div>

            {/* Course Overview */}
            <div className="bg-white rounded-2xl border border-slate-200 p-8 shadow-sm hover:shadow-md transition-shadow">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-50 to-blue-100 flex items-center justify-center">
                  <LayoutDashboard size={20} className="text-blue-600" />
                </div>
                <h2 className="text-xl font-bold text-slate-900">Course Overview</h2>
              </div>
              
              <div className="prose prose-slate max-w-none text-slate-600 leading-relaxed space-y-4">
                <p>{course.description}</p>
              </div>

              {/* Dynamic Objectives */}
              <div className="mt-8 pt-8 border-t border-slate-100">
                <div className="flex items-center gap-3 mb-5">
                  <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-green-50 to-green-100 flex items-center justify-center">
                    <Target size={18} className="text-green-600" />
                  </div>
                  <h3 className="text-lg font-bold text-slate-900">What You'll Learn</h3>
                </div>

                <div className="grid sm:grid-cols-2 gap-4">
                  {learningObjectives.map((item, i) => (
                    <div key={i} className="flex items-start gap-3 text-sm text-slate-700 group">
                      <div className="w-5 h-5 rounded-lg bg-gradient-to-br from-green-50 to-green-100 flex items-center justify-center shrink-0 mt-0.5 group-hover:scale-110 transition-transform">
                        <CheckCircle2 size={14} className="text-green-600" />
                      </div>
                      <span className="leading-relaxed">{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Dynamic Prerequisites */}
            <div className="bg-white rounded-2xl border border-slate-200 p-8 shadow-sm hover:shadow-md transition-shadow">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-amber-50 to-amber-100 flex items-center justify-center">
                  <Zap size={18} className="text-amber-600" />
                </div>
                <h3 className="text-lg font-bold text-slate-900">Prerequisites</h3>
              </div>
              <div className="space-y-3">
                {prerequisites.map((req, i) => (
                  <div 
                    key={i} 
                    className="flex items-center gap-3 text-sm text-slate-700 p-3 rounded-lg hover:bg-slate-50 transition-colors"
                  >
                    <div className="w-2 h-2 rounded-full bg-gradient-to-r from-amber-400 to-amber-500" />
                    <span>{req}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* RIGHT COLUMN: Course Content */}
          <div className="lg:col-span-4">
            <div className="sticky top-6 space-y-6">
              
              {/* Course Content Card */}
              <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-lg shadow-slate-200/50">
                {/* Header */}
                <div className="bg-gradient-to-r from-slate-50 to-white border-b border-slate-200 p-5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-50 to-blue-100 flex items-center justify-center">
                        <MonitorPlay size={18} className="text-blue-600" />
                      </div>
                      <h3 className="font-bold text-slate-900">Course Content</h3>
                    </div>
                    <div className="px-3 py-1 bg-white rounded-lg border border-slate-200 shadow-sm">
                      <span className="text-xs text-slate-600 font-semibold">
                        {stats.completedCount} / {stats.totalCount}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Scrollable List */}
                <div 
                  className="max-h-[600px] overflow-y-auto"
                  style={{ scrollbarWidth: 'thin', scrollbarColor: '#cbd5e1 #f8fafc' }}
                >
                  {allModules.map((module, index) => {
                    const isFinalExam = index === allModules.length - 1;
                    const isLocked = isFinalExam && stats.percentage !== 100;
                    return (
                      <ModuleSection 
                        key={index} 
                        module={module} 
                        index={index} 
                        trackId={trackId} 
                        isLocked={isLocked} 
                        isFinalExam={isFinalExam} 
                      />
                    );
                  })}
                </div>
              </div>

              {/* Enhanced Instructor Card */}
              <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm hover:shadow-md transition-shadow">
                <div className="flex items-start gap-4">
                  <div className="w-16 h-16 rounded-2xl overflow-hidden shrink-0 shadow-sm bg-slate-100">
                    <img 
                      src="https://media.licdn.com/dms/image/v2/D5603AQGmaD34-rZnfw/profile-displayphoto-scale_100_100/B56Zfv8aanGUAg-/0/1752077287096?e=1765411200&v=beta&t=HJQ8Cyws4fMFcwS1d4kRrJKdAGHVnklzW1VW_p6GnVw"
                      alt="Instructor"
                      className="w-full h-full object-cover"
                    />
                  </div>

                  <div className="flex-1 min-w-0">
                    <h4 className="font-bold text-slate-900 mb-1">Aniket Tyagi</h4>
                    <p className="text-xs text-slate-500 mb-3">Lead Security Engineer</p>
                    <div className="flex items-center gap-3 text-xs text-slate-600 mb-4">
                      <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-50 rounded-lg">
                        <GraduationCap size={14} className="text-slate-400" />
                        <span className="font-medium">6+ Years Experience</span>
                      </div>
                    </div>
                    <button className="text-sm font-semibold text-blue-600 hover:text-blue-700 transition-colors flex items-center gap-1 group">
                      <span>Connect Now!</span>
                      <ArrowRight size={14} className="group-hover:translate-x-1 transition-transform" />
                    </button>
                  </div>
                </div>
              </div>

            </div>
          </div>

        </div>
      </div>

      {/* NEW MODERN SECTION */}
      <div className="border-t border-slate-100 bg-gradient-to-b from-white to-slate-50/70">
        <div className="max-w-7xl mx-auto px-6 py-10 md:py-12">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-8 mb-8">
            <div className="max-w-xl">
              <p className="text-xs font-semibold tracking-wide text-blue-600 uppercase mb-2">
                Beyond the syllabus
              </p>
              <h2 className="text-2xl md:text-3xl font-bold text-slate-900 mb-3">
                Learn with structure, progress with confidence.
              </h2>
              <p className="text-sm md:text-base text-slate-600">
              This ACS Internship is built to support your long-term security journey, providing clear milestones, 
              practical learning, and skills that translate directly into real-world audits and assessments.
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-white border border-slate-200 text-xs text-slate-700 shadow-sm">
                <Shield size={14} className="text-blue-600" />
                <span>Industry-aligned content</span>
              </div>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-white border border-slate-200 text-xs text-slate-700 shadow-sm">
                <Award size={14} className="text-emerald-600" />
                <span>Certificate on completion</span>
              </div>
            </div>
          </div>

          <div className="grid gap-5 md:grid-cols-3">
            <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm hover:shadow-md transition-all">
              <div className="w-9 h-9 rounded-lg bg-blue-50 flex items-center justify-center mb-3">
                <BookOpen size={18} className="text-blue-600" />
              </div>
              <h3 className="text-sm font-semibold text-slate-900 mb-2">
                Structured, not rigid
              </h3>
              <p className="text-xs md:text-sm text-slate-600 leading-relaxed">
                Stay aligned with the tools, techniques, and workflows used by professional security teams. 
                Earn a certificate that reflects real capability, not just course completion.
              </p>
            </div>

            <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm hover:shadow-md transition-all">
              <div className="w-9 h-9 rounded-lg bg-emerald-50 flex items-center justify-center mb-3">
                <Code2 size={18} className="text-emerald-600" />
              </div>
              <h3 className="text-sm font-semibold text-slate-900 mb-2">
                Structured, not restrictive
              </h3>
              <p className="text-xs md:text-sm text-slate-600 leading-relaxed">
                Follow a clear, module-based path while keeping the flexibility to learn at your pace. 
                Revisit important concepts anytime and build a strong foundation step by step.
              </p>
            </div>

            <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-sm hover:shadow-md transition-all">
              <div className="w-9 h-9 rounded-lg bg-indigo-50 flex items-center justify-center mb-3">
                <TrendingUp size={18} className="text-indigo-600" />
              </div>
              <h3 className="text-sm font-semibold text-slate-900 mb-2">
                Career-focused outcomes
              </h3>
              <p className="text-xs md:text-sm text-slate-600 leading-relaxed">
                Track your progress, complete the final assessment, and earn a certificate that helps you stand out to hiring managers, 
                clients, and collaborators in the security industry.
              </p>
            </div>
          </div>
        </div>
      </div>

    </div>
  );
};

export default CourseDetail;