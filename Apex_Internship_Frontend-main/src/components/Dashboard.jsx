import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { BookOpen, Clock, Lock, Loader2, Crown } from 'lucide-react';
import courseData from '../data/course.json';

// --- ANIMATION VARIANTS ---
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      duration: 0.6,
      staggerChildren: 0.2
    }
  }
};

const itemVariants = {
  hidden: { y: 20, opacity: 0 },
  visible: {
    y: 0,
    opacity: 1,
    transition: {
      duration: 0.5,
      ease: "easeOut"
    }
  }
};

const Dashboard = () => {
  const [course, setCourse] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  // --- FETCH COURSE DATA ---
  useEffect(() => {
    const fetchCourseData = async () => {
      try {
        // Simulate loading delay
        await new Promise(resolve => setTimeout(resolve, 1000));
        setCourse(courseData);
      } catch (error) {
        console.error('Error fetching course data:', error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchCourseData();
  }, []);

  // --- LOADING STATE ---
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="flex items-center gap-3">
          <Loader2 className="w-6 h-6 animate-spin text-indigo-600" />
          <span className="text-slate-600">Loading course...</span>
        </div>
      </div>
    );
  }

  // --- LIMITED ACCESS STATE ---
  if (!course?.hasAccess) {
    return (
      <motion.div 
        className="space-y-6 mt-6 pb-8"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        
        {/* --- HEADER --- */}
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-700 pb-5">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-1">ACS Dashboard</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">Limited access to course content</p>
          </div>
        </div>

        {/* --- LIMITED ACCESS COURSE CARD --- */}
        <motion.div
          variants={itemVariants}
          className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-sm overflow-hidden"
        >
          {/* Large Gradient Banner Header */}
          <div className="bg-gradient-to-r from-purple-600 via-indigo-600 to-blue-600 p-8 text-white relative overflow-hidden">
            {/* Background Pattern */}
            <div className="absolute inset-0 bg-black/10"></div>
            <div className="absolute inset-0 bg-gradient-to-br from-transparent via-transparent to-black/20"></div>
            
            {/* Content */}
            <div className="relative z-10">
              <div className="flex items-start justify-between mb-6">
                <div className="flex-1">
                  {/* Course Title */}
                  <h2 className="text-3xl md:text-4xl font-bold mb-3 leading-tight">
                    {course.title}
                  </h2>
                  
                  {/* Tagline */}
                  <p className="text-lg md:text-xl text-purple-100 mb-4 font-medium">
                    Master the Art of Ethical Hacking
                  </p>
                  
                  {/* Short Description */}
                  <p className="text-purple-50 mb-6 max-w-2xl leading-relaxed">
                    {course.description}
                  </p>
                  
                  {/* Course Meta */}
                  <div className="flex items-center gap-4 text-sm">
                    <span className="flex items-center gap-1.5">
                      <Clock size={14} />
                      <span>{course.duration}</span>
                    </span>
                    <span className="px-3 py-1 bg-white/20 rounded-full text-xs font-semibold">
                      {course.difficulty}
                    </span>
                    <span className="px-3 py-1 bg-purple-400/30 rounded-full text-xs font-semibold">
                      1 Module Access
                    </span>
                  </div>
                </div>
                
                {/* Lock Icon for Limited Access */}
                <div className="ml-6 flex-shrink-0">
                  <div className="p-4 bg-white/10 backdrop-blur-sm rounded-2xl border border-white/20">
                    <Lock className="w-8 h-8 text-white" />
                  </div>
                </div>
              </div>
            </div>
            
            {/* Decorative Elements */}
            <div className="absolute top-4 right-4 w-20 h-20 bg-white/5 rounded-full blur-xl"></div>
            <div className="absolute bottom-4 left-4 w-32 h-32 bg-white/5 rounded-full blur-2xl"></div>
          </div>

          {/* Course Content */}
          <div className="p-6">
            {/* Limited Access Message */}
            <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-3">
                <Crown className="w-5 h-5 text-amber-600 dark:text-amber-400" />
                <div>
                  <h3 className="font-semibold text-slate-900 dark:text-slate-100">Limited Access</h3>
                  <p className="text-sm text-slate-600 dark:text-slate-300">You have access to 1 module. Upgrade to unlock all {course.modules.length} modules.</p>
                </div>
              </div>
            </div>

            {/* Single Module Access */}
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-3">Available Module</h3>
              <div className="space-y-2">
                {course.modules.slice(0, 1).map((module) => (
                  <div key={module.id} className="flex items-center justify-between p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                    <div>
                      <h4 className="font-medium text-slate-900 dark:text-slate-100 text-sm flex items-center gap-2">
                        {module.title}
                        <span className="px-2 py-1 bg-green-100 dark:bg-green-800 text-green-700 dark:text-green-300 text-xs font-semibold rounded-md">
                          FREE
                        </span>
                      </h4>
                      <p className="text-xs text-slate-500 dark:text-slate-400">{module.lessons} lessons • {module.duration}</p>
                    </div>
                    <BookOpen className="w-4 h-4 text-green-600 dark:text-green-400" />
                  </div>
                ))}
              </div>
            </div>

            {/* Locked Modules Preview */}
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-3">Locked Modules</h3>
              <div className="space-y-2">
                {course.modules.slice(1).map((module) => (
                  <div key={module.id} className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-700/50 rounded-lg opacity-60">
                    <div>
                      <h4 className="font-medium text-slate-900 dark:text-slate-100 text-sm">{module.title}</h4>
                      <p className="text-xs text-slate-500 dark:text-slate-400">{module.lessons} lessons • {module.duration}</p>
                    </div>
                    <Lock className="w-4 h-4 text-slate-400 dark:text-slate-500" />
                  </div>
                ))}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3">
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="flex-1 px-6 py-3 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 transition-colors flex items-center justify-center gap-2"
              >
                <BookOpen size={16} />
                Start Free Module
              </motion.button>
              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="flex-1 px-6 py-3 bg-indigo-600 text-white font-semibold rounded-lg hover:bg-indigo-700 transition-colors"
              >
                Upgrade for Full Access
              </motion.button>
            </div>
          </div>
        </motion.div>
      </motion.div>
    );
  }

  // --- COURSE DISPLAY STATE ---
  return (
    <motion.div 
      className="space-y-6 mt-6 pb-8"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
    >
      
      {/* --- HEADER --- */}
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-700 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-1">ACS Course Dashboard</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">Continue your learning journey</p>
        </div>
      </div>

      {/* --- SINGLE COURSE CARD --- */}
      <motion.div
        variants={itemVariants}
        className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-sm overflow-hidden"
      >
        {/* Large Gradient Banner Header */}
        <div className="bg-gradient-to-r from-purple-600 via-indigo-600 to-blue-600 p-8 text-white relative overflow-hidden">
          {/* Background Pattern */}
          <div className="absolute inset-0 bg-black/10"></div>
          <div className="absolute inset-0 bg-gradient-to-br from-transparent via-transparent to-black/20"></div>
          
          {/* Content */}
          <div className="relative z-10">
            <div className="flex items-start justify-between mb-6">
              <div className="flex-1">
                {/* Course Title */}
                <h2 className="text-3xl md:text-4xl font-bold mb-3 leading-tight">
                  {course.title}
                </h2>
                
                {/* Tagline */}
                <p className="text-lg md:text-xl text-purple-100 mb-4 font-medium">
                  Master the Art of Ethical Hacking
                </p>
                
                {/* Short Description */}
                <p className="text-purple-50 mb-6 max-w-2xl leading-relaxed">
                  {course.description}
                </p>
                
                {/* Course Meta */}
                <div className="flex items-center gap-4 text-sm">
                  <span className="flex items-center gap-1.5">
                    <Clock size={14} />
                    <span>{course.duration}</span>
                  </span>
                  <span className="px-3 py-1 bg-white/20 rounded-full text-xs font-semibold">
                    {course.difficulty}
                  </span>
                  <span className="px-3 py-1 bg-green-400/30 rounded-full text-xs font-semibold">
                    Full Access
                  </span>
                </div>
              </div>
              
              {/* Book Icon for Full Access */}
              <div className="ml-6 flex-shrink-0">
                <div className="p-4 bg-white/10 backdrop-blur-sm rounded-2xl border border-white/20">
                  <BookOpen className="w-8 h-8 text-white" />
                </div>
              </div>
            </div>
          </div>
          
          {/* Decorative Elements */}
          <div className="absolute top-4 right-4 w-20 h-20 bg-white/5 rounded-full blur-xl"></div>
          <div className="absolute bottom-4 left-4 w-32 h-32 bg-white/5 rounded-full blur-2xl"></div>
        </div>

        {/* Course Content */}
        <div className="p-6">
          {/* Course Stats */}
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="text-center">
              <p className="text-2xl font-bold text-slate-900">{course.stats.total_students}</p>
              <p className="text-xs text-slate-500">Students</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-slate-900">{course.stats.average_rating}</p>
              <p className="text-xs text-slate-500">Rating</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-slate-900">{course.stats.completion_rate}%</p>
              <p className="text-xs text-slate-500">Completion</p>
            </div>
          </div>

          {/* Modules Preview */}
          <div className="mb-6">
            <h3 className="text-sm font-semibold text-slate-600 uppercase tracking-wider mb-3">Course Modules</h3>
            <div className="space-y-2">
              {course.modules.slice(0, 3).map((module) => (
                <div key={module.id} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                  <div>
                    <h4 className="font-medium text-slate-900 text-sm">{module.title}</h4>
                    <p className="text-xs text-slate-500">{module.lessons} lessons • {module.duration}</p>
                  </div>
                  <Lock className="w-4 h-4 text-slate-400" />
                </div>
              ))}
            </div>
          </div>

          {/* Action Button */}
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            className="w-full px-6 py-3 bg-indigo-600 text-white font-semibold rounded-lg hover:bg-indigo-700 transition-colors flex items-center justify-center gap-2"
          >
            <BookOpen size={16} />
            Start Learning
          </motion.button>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default Dashboard;
