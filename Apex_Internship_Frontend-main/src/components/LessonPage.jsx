import React, { useState, useEffect } from 'react';
import { useParams, Link, Navigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronLeft, Video, BookOpen, Clock, PlayCircle, ChevronDown, CheckCircle2, FileText, Download, Bookmark, AlertCircle, ExternalLink } from 'lucide-react';
import { courseData } from './utils/courseinfo'; 

// --- Sub-Component: Sidebar Lesson Item ---
const SidebarLessonItem = ({ lesson, index, currentLessonId }) => {
    const isActive = lesson.id === currentLessonId;
    const Icon = lesson.completed ? CheckCircle2 : Video;
    // FIX: Encode ID here too
    const safeLessonId = encodeURIComponent(lesson.id);
    
    return (
        <Link 
            to={`/lesson/${safeLessonId}`} 
            className={`group flex items-start gap-3 p-3 rounded-lg transition-all duration-200 ${isActive ? 'bg-indigo-50 text-indigo-900 shadow-sm' : lesson.completed ? 'bg-emerald-50/50 text-slate-600' : 'bg-white text-slate-700 hover:bg-slate-50'}`}
        >
            <div className={`w-6 h-6 rounded-md flex items-center justify-center shrink-0 transition-colors ${isActive ? 'bg-indigo-600 text-white' : lesson.completed ? 'bg-emerald-500 text-white' : 'bg-slate-100 text-slate-400 group-hover:bg-slate-200'}`}>
                <Icon size={14} strokeWidth={2.5} />
            </div>
            <div className="flex-1 min-w-0">
                <p className={`text-sm leading-snug font-medium ${isActive ? 'font-semibold' : ''}`}>{index}. {lesson.title}</p>
            </div>
        </Link>
    );
};

// --- Sub-Component: Progress Stats (Same as before) ---
const ProgressStats = ({ watchProgress }) => {
    const percentage = Math.round(watchProgress * 100);
    const isComplete = percentage >= 90;
    return (
        <div className="flex items-center gap-3 p-4 bg-slate-50 rounded-lg border border-slate-200">
            <div className="flex-1">
                <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden">
                    <motion.div className={`h-full rounded-full ${isComplete ? 'bg-emerald-500' : 'bg-indigo-600'}`} initial={{ width: 0 }} animate={{ width: `${percentage}%` }} transition={{ duration: 0.3 }} />
                </div>
            </div>
        </div>
    );
};

// --- Main Component: LessonPage ---
const LessonPage = () => {
    const { lessonId, trackId } = useParams();
    const [videoUrl, setVideoUrl] = useState(null); 
    const [currentLesson, setCurrentLesson] = useState(null);
    const [currentCourse, setCurrentCourse] = useState(null);
    const [isOpen, setIsOpen] = useState({});
    const [isLoading, setIsLoading] = useState(true); 
    const [watchProgress, setWatchProgress] = useState(0);

    useEffect(() => {
        let foundLesson = null;
        let foundCourse = null;
        let initialOpenState = {};
        
        setIsLoading(true);

        // FIX: Decode the ID so we can find it in the data (turns "risk%26process" back to "risk&process")
        const targetId = decodeURIComponent(lessonId);
        
        for (const courseKey in courseData) {
            const course = courseData[courseKey];
            let moduleIndex = 0;
            for (const module of course.modules) {
                const lesson = module.lessons.find(l => l.id === targetId);
                
                if (lesson) {
                    foundLesson = lesson;
                    foundCourse = course;
                    initialOpenState[moduleIndex] = true; 
                    break;
                }
                moduleIndex++;
            }
            if (foundLesson) break;
        }

        setCurrentLesson(foundLesson);
        setCurrentCourse(foundCourse);
        setIsOpen(initialOpenState);
        
        if (foundLesson) {
            setVideoUrl(`https://secure-cdn.yourlms.com/stream/${targetId}?token=jwt12345`);
        }
        
        setIsLoading(false); 

    }, [lessonId]); // Trigger re-run when ID changes

    if (isLoading) {
        return <div className="flex items-center justify-center h-screen w-full bg-slate-50"><p>Loading...</p></div>;
    }
    
    if (!currentLesson || !currentCourse) {
        // This is where it was redirecting because it couldn't find the lesson
        return <Navigate to="/courses" replace />;
    }
    
    // (Rest of the component logic for Sidebar, Video Player, etc.)
    const backLink = trackId ? `/track/${trackId}/courses/${currentCourse.id}` : `/courses/${currentCourse.id}`;
    const toggleModule = (index) => setIsOpen(prev => ({ ...prev, [index]: !prev[index] }));
    const currentModule = currentCourse.modules.find(module => module.lessons.some(lesson => lesson.id === currentLesson.id));

    return (
        <div className="flex h-screen bg-slate-50">
            {/* Sidebar */}
            <motion.div initial={{ x: -20, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="w-80 bg-white border-r border-slate-200 overflow-y-auto flex flex-col">
                <div className="p-6 border-b border-slate-200">
                    <Link to={backLink} className="inline-flex items-center gap-2 text-sm font-semibold text-slate-600 hover:text-indigo-600 transition-colors mb-4">
                        <ChevronLeft size={16} /> Back to Course
                    </Link>
                    <h2 className="text-lg font-bold text-slate-900">{currentCourse.title}</h2>
                </div>
                <div className="p-4 space-y-2 flex-1">
                    {currentCourse.modules.map((module, index) => (
                        <div key={index} className="border border-slate-200 rounded-lg overflow-hidden bg-white shadow-sm">
                            <button className="w-full flex items-center justify-between p-4 text-left hover:bg-slate-50" onClick={() => toggleModule(index)}>
                                <span className="font-semibold text-slate-900 text-sm">{module.title}</span>
                                <ChevronDown size={18} className={`transition-transform ${isOpen[index] ? 'rotate-180' : ''}`} />
                            </button>
                            <AnimatePresence>
                                {isOpen[index] && (
                                    <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden bg-slate-50">
                                        <div className="p-2 space-y-1">
                                            {module.lessons.map((lesson, i) => (
                                                <SidebarLessonItem key={i} lesson={lesson} index={`${index + 1}.${i + 1}`} currentLessonId={currentLesson.id} />
                                            ))}
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>
                    ))}
                </div>
            </motion.div>

            {/* Main Content */}
            <div className="flex-1 overflow-y-auto">
                <div className="max-w-6xl mx-auto p-8">
                    <h1 className="text-3xl font-bold text-slate-900 mb-6">{currentLesson.title}</h1>
                    <div className="relative aspect-video bg-slate-900 rounded-xl shadow-2xl mb-8 overflow-hidden">
                        {videoUrl && <video src={videoUrl} controls className="w-full h-full object-cover" />}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default LessonPage;