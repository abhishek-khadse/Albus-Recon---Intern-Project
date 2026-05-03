import React from 'react';
import { Award, CheckCircle2, Download, Clock, TrendingUp, BookOpen } from 'lucide-react';

const MyGrades = () => {
  const modules = [
    { id: 1, name: "Cyber Security Fundamentals", score: 98, status: "Passed", date: "Sep 15, 2025", credits: 4, grade: "A+" },
    { id: 2, name: "Networking Essentials", score: 92, status: "Passed", date: "Sep 30, 2025", credits: 4, grade: "A" },
    { id: 3, name: "Programming with Python", score: 88, status: "Passed", date: "Oct 10, 2025", credits: 6, grade: "A" },
    { id: 4, name: "Web Security & VAPT", score: null, status: "In Progress", date: "-", credits: 8, grade: "-" },
  ];

  // Calculate GPA Logic
  const completedModules = modules.filter(m => m.score !== null);
  const totalCompleted = completedModules.length;
  const totalModules = modules.length;
  const avgScore = (completedModules.reduce((acc, curr) => acc + curr.score, 0) / completedModules.length).toFixed(1);
  const totalCredits = completedModules.reduce((acc, curr) => acc + curr.credits, 0);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-indigo-50/30 to-slate-100 p-4 md:p-8">
      <div className="max-w-6xl mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex items-center justify-between mb-2">
          <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-1">Academic Performance</h1>
            <p className="text-slate-600">Track your progress and achievements</p>
          </div>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white border border-indigo-200/60 rounded-2xl p-5 shadow-lg shadow-indigo-100/50">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 bg-indigo-50 rounded-xl flex items-center justify-center">
                <Award className="text-indigo-600" size={20} />
              </div>
              <span className="text-xs font-bold text-indigo-600 bg-indigo-50 px-2 py-1 rounded-lg">Grade</span>
            </div>
            <p className="text-3xl font-black text-slate-900 mb-1">{avgScore}%</p>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Average Score</p>
          </div>

          <div className="bg-white border border-emerald-200/60 rounded-2xl p-5 shadow-lg shadow-emerald-100/50">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 bg-emerald-50 rounded-xl flex items-center justify-center">
                <CheckCircle2 className="text-emerald-600" size={20} />
              </div>
              <span className="text-xs font-bold text-emerald-600 bg-emerald-50 px-2 py-1 rounded-lg">Passed</span>
            </div>
            <p className="text-3xl font-black text-slate-900 mb-1">{totalCompleted}/{totalModules}</p>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Courses Completed</p>
          </div>

          <div className="bg-white border border-violet-200/60 rounded-2xl p-5 shadow-lg shadow-violet-100/50">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 bg-violet-50 rounded-xl flex items-center justify-center">
                <BookOpen className="text-violet-600" size={20} />
              </div>
              <span className="text-xs font-bold text-violet-600 bg-violet-50 px-2 py-1 rounded-lg">Credits</span>
            </div>
            <p className="text-3xl font-black text-slate-900 mb-1">{totalCredits}</p>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Credits Earned</p>
          </div>

          <div className="bg-white border border-amber-200/60 rounded-2xl p-5 shadow-lg shadow-amber-100/50">
            <div className="flex items-center justify-between mb-3">
              <div className="w-10 h-10 bg-amber-50 rounded-xl flex items-center justify-center">
                <TrendingUp className="text-amber-600" size={20} />
              </div>
              <span className="text-xs font-bold text-amber-600 bg-amber-50 px-2 py-1 rounded-lg">Rank</span>
            </div>
            <p className="text-3xl font-black text-slate-900 mb-1">A</p>
            <p className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Overall Grade</p>
          </div>
        </div>

        {/* Grade Table */}
        <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
          <div className="px-6 md:px-8 py-6 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xl font-bold text-slate-900">Course Grades</h3>
                <p className="text-sm text-slate-500 mt-1">Detailed performance breakdown</p>
              </div>
              <button className="hidden md:flex items-center gap-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-xl transition-colors shadow-lg shadow-indigo-200">
                <Download size={16} />
                Export Transcript
              </button>
            </div>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200">
                  <th className="px-6 md:px-8 py-4 text-left">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Course Name</span>
                  </th>
                  <th className="px-6 py-4 text-left hidden md:table-cell">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Completion Date</span>
                  </th>
                  <th className="px-6 py-4 text-center">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Credits</span>
                  </th>
                  <th className="px-6 py-4 text-center">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Score</span>
                  </th>
                  <th className="px-6 py-4 text-center">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Grade</span>
                  </th>
                  <th className="px-6 md:px-8 py-4 text-right">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Status</span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {modules.map((module) => (
                  <tr key={module.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-6 md:px-8 py-5">
                      <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-xs font-bold ${
                          module.status === 'Passed' 
                            ? 'bg-indigo-50 text-indigo-600' 
                            : 'bg-slate-100 text-slate-500'
                        }`}>
                          {module.id}
                        </div>
                        <div>
                          <p className="text-sm font-bold text-slate-900">{module.name}</p>
                          <p className="text-xs text-slate-500 md:hidden">{module.date}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-5 text-sm text-slate-600 font-medium hidden md:table-cell">
                      {module.date}
                    </td>
                    <td className="px-6 py-5 text-center">
                      <span className="inline-flex items-center justify-center w-8 h-8 bg-slate-100 rounded-lg text-sm font-bold text-slate-700">
                        {module.credits}
                      </span>
                    </td>
                    <td className="px-6 py-5 text-center">
                      {module.score ? (
                        <span className={`text-lg font-black ${
                          module.score >= 95 ? 'text-emerald-600' : 
                          module.score >= 90 ? 'text-indigo-600' : 
                          'text-slate-700'
                        }`}>
                          {module.score}%
                        </span>
                      ) : (
                        <span className="text-slate-400 font-medium">-</span>
                      )}
                    </td>
                    <td className="px-6 py-5 text-center">
                      {module.grade !== "-" ? (
                        <span className={`inline-flex items-center justify-center w-10 h-10 rounded-lg text-sm font-black ${
                          module.grade === 'A+' ? 'bg-emerald-100 text-emerald-700 border border-emerald-200' :
                          module.grade === 'A' ? 'bg-indigo-100 text-indigo-700 border border-indigo-200' :
                          'bg-slate-100 text-slate-700 border border-slate-200'
                        }`}>
                          {module.grade}
                        </span>
                      ) : (
                        <span className="text-slate-400 font-medium">-</span>
                      )}
                    </td>
                    <td className="px-6 md:px-8 py-5 text-right">
                      <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold border ${
                        module.status === 'Passed' 
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200' 
                          : 'bg-amber-50 text-amber-700 border-amber-200'
                      }`}>
                        {module.status === 'Passed' ? (
                          <CheckCircle2 size={14} />
                        ) : (
                          <Clock size={14} />
                        )}
                        {module.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Mobile Export Button */}
          <div className="p-4 md:p-6 bg-slate-50/50 border-t border-slate-200">
            <button className="md:hidden w-full flex items-center justify-center gap-2 px-4 py-3 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-xl transition-colors">
              <Download size={16} />
              Export Transcript
            </button>
            <p className="text-center text-xs text-slate-500 mt-3 font-medium">
              Last updated: November 25, 2025
            </p>
          </div>
        </div>

        {/* Grading Scale */}
        <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
          <div className="px-6 md:px-8 py-5 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-indigo-50 rounded-xl flex items-center justify-center">
                <Award className="text-indigo-600" size={20} />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-900">Grading Scale</h3>
                <p className="text-sm text-slate-500">Official grade distribution system</p>
              </div>
            </div>
          </div>
          
          <div className="p-6 md:p-8">
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              <div className="bg-gradient-to-br from-emerald-50 to-emerald-100/50 border border-emerald-200 rounded-xl p-4 text-center">
                <div className="text-2xl font-black text-emerald-700 mb-1">A+</div>
                <div className="text-xs font-bold text-emerald-600">95 - 100</div>
                <div className="text-[10px] font-semibold text-emerald-600/70 uppercase mt-1">Excellent</div>
              </div>
              
              <div className="bg-gradient-to-br from-emerald-50/70 to-emerald-100/30 border border-emerald-200/70 rounded-xl p-4 text-center">
                <div className="text-2xl font-black text-emerald-600 mb-1">A</div>
                <div className="text-xs font-bold text-emerald-600/80">90 - 94</div>
                <div className="text-[10px] font-semibold text-emerald-600/60 uppercase mt-1">Outstanding</div>
              </div>
              
              <div className="bg-gradient-to-br from-indigo-50 to-indigo-100/50 border border-indigo-200 rounded-xl p-4 text-center">
                <div className="text-2xl font-black text-indigo-700 mb-1">B+</div>
                <div className="text-xs font-bold text-indigo-600">85 - 89</div>
                <div className="text-[10px] font-semibold text-indigo-600/70 uppercase mt-1">Very Good</div>
              </div>
              
              <div className="bg-gradient-to-br from-indigo-50/70 to-indigo-100/30 border border-indigo-200/70 rounded-xl p-4 text-center">
                <div className="text-2xl font-black text-indigo-600 mb-1">B</div>
                <div className="text-xs font-bold text-indigo-600/80">80 - 84</div>
                <div className="text-[10px] font-semibold text-indigo-600/60 uppercase mt-1">Good</div>
              </div>
              
              <div className="bg-gradient-to-br from-violet-50 to-violet-100/50 border border-violet-200 rounded-xl p-4 text-center">
                <div className="text-2xl font-black text-violet-700 mb-1">C+</div>
                <div className="text-xs font-bold text-violet-600">75 - 79</div>
                <div className="text-[10px] font-semibold text-violet-600/70 uppercase mt-1">Satisfactory</div>
              </div>
              
              <div className="bg-gradient-to-br from-violet-50/70 to-violet-100/30 border border-violet-200/70 rounded-xl p-4 text-center">
                <div className="text-2xl font-black text-violet-600 mb-1">C</div>
                <div className="text-xs font-bold text-violet-600/80">70 - 74</div>
                <div className="text-[10px] font-semibold text-violet-600/60 uppercase mt-1">Acceptable</div>
              </div>
            </div>
            
            <div className="mt-6 pt-6 border-t border-slate-200">
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <div className="flex items-center gap-2 text-xs text-slate-600">
                  <div className="w-2 h-2 bg-slate-400 rounded-full"></div>
                  <span className="font-medium">Minimum passing grade: <span className="font-bold text-slate-900">70%</span></span>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-600">
                  <div className="w-2 h-2 bg-slate-400 rounded-full"></div>
                  <span className="font-medium">Grade point calculated on 4.0 scale</span>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};

export default MyGrades;