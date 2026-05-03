import React from 'react';
import { Link, useParams, Navigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
    ChevronLeft, BookOpen, Hash, ArrowRight, BarChart, Clock, 
    Zap, CheckCircle, Lock, Blocks, Award, TrendingUp, Target
} from 'lucide-react';
import { webSecurityCourses, BlockchainSecurityCourses } from '../utils/tracksinfo'; 

const TRACK_CONFIG = {
    'web-security-track': {
        title: "Web & API Security Track",
        description: "Master enterprise-grade web application security through hands-on penetration testing scenarios and API vulnerability assessments.",
        icon: Hash,
        courses: webSecurityCourses,
        gradient: "from-indigo-600 to-indigo-700",
        accentColor: "indigo",
        glowColor: "rgba(99, 102, 241, 0.15)"
    },
    'blockchain-security-track': {
        title: "Blockchain & Smart Contract Security",
        description: "Develop expertise in smart contract auditing, DeFi security protocols, and blockchain vulnerability analysis.",
        icon: Blocks, 
        courses: BlockchainSecurityCourses,
        gradient: "from-emerald-600 to-emerald-700",
        accentColor: "emerald",
        glowColor: "rgba(16, 185, 129, 0.15)"
    }
};

// --- ANIMATION VARIANTS ---
const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
        opacity: 1,
        transition: { staggerChildren: 0.06, delayChildren: 0.15 }
    }
};

const cardVariants = {
    hidden: { opacity: 0, y: 15 },
    visible: {
        opacity: 1, 
        y: 0, 
        transition: { duration: 0.4, ease: [0.4, 0, 0.2, 1] }
    }
};

// --- Sub-Component: Course Card ---
const TrackCourseCard = ({ course, index, isCompleted, isLocked, trackId, config }) => {
    const courseDetailsPath = `/track/${trackId}/courses/${course.id}`;
    const buttonText = isLocked ? 'Locked' : (isCompleted ? 'Review Course' : 'Begin Module');
    const StatusIcon = isLocked ? Lock : (isCompleted ? CheckCircle : Zap);
    
    const getCardStyles = () => {
        if (isLocked) {
            return {
                border: 'border-slate-200',
                bg: 'bg-slate-50/50',
                iconBg: 'bg-slate-100',
                iconColor: 'text-slate-400',
                textColor: 'text-slate-400',
                badgeBg: 'bg-slate-100',
                badgeText: 'text-slate-500'
            };
        }
        if (isCompleted) {
            return {
                border: 'border-emerald-200',
                bg: 'bg-white',
                iconBg: 'bg-emerald-50',
                iconColor: 'text-emerald-600',
                textColor: 'text-emerald-600',
                badgeBg: 'bg-emerald-50',
                badgeText: 'text-emerald-700'
            };
        }
        return {
            border: `border-${config.accentColor}-200`,
            bg: 'bg-white',
            iconBg: `bg-${config.accentColor}-50`,
            iconColor: `text-${config.accentColor}-600`,
            textColor: `text-${config.accentColor}-600`,
            badgeBg: `bg-${config.accentColor}-50`,
            badgeText: `text-${config.accentColor}-700`
        };
    };

    const styles = getCardStyles();

    return (
        <motion.div 
            variants={cardVariants}
            whileHover={!isLocked ? { y: -2, transition: { duration: 0.2 } } : {}}
            className={`group relative ${styles.bg} border ${styles.border} rounded-lg shadow-sm hover:shadow-md transition-all duration-300`}
        >
            <div className="relative p-6">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                    
                    {/* Left Section */}
                    <div className="flex items-start gap-5 flex-1 min-w-0">
                        {/* Status Indicator */}
                        <div className={`flex-shrink-0 w-12 h-12 rounded-lg ${styles.iconBg} ${styles.iconColor} flex items-center justify-center`}>
                            <StatusIcon size={20} strokeWidth={2} /> 
                        </div>
                        
                        {/* Content */}
                        <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-2">
                                <span className={`inline-flex items-center px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider rounded ${styles.badgeBg} ${styles.badgeText}`}>
                                    Module {index + 1}
                                </span>
                                {isCompleted && (
                                    <span className="inline-flex items-center gap-1 px-2 py-1 text-[10px] font-bold uppercase tracking-wider rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                                        <CheckCircle size={10} /> Completed
                                    </span>
                                )}
                            </div>
                            
                            <h3 className="text-lg font-bold text-slate-900 mb-1.5 leading-tight">
                                {course.title}
                            </h3>
                            
                            {course.description && (
                                <p className="text-sm text-slate-600 leading-relaxed line-clamp-2">
                                    {course.description}
                                </p>
                            )}
                        </div>
                    </div>

                    {/* Right Section */}
                    <div className="flex flex-col sm:flex-row lg:flex-col xl:flex-row items-start sm:items-center lg:items-end xl:items-center gap-4 lg:gap-3 xl:gap-4">
                        {/* Metrics */}
                        <div className="flex items-center gap-4 text-xs font-medium">
                            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-50 rounded-md text-slate-600 border border-slate-200">
                                <BarChart size={13} strokeWidth={2} /> 
                                <span>{course.level || 'Intermediate'}</span>
                            </div>
                            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-50 rounded-md text-slate-600 border border-slate-200">
                                <Clock size={13} strokeWidth={2} /> 
                                <span>{course.duration || 'N/A'}</span>
                            </div>
                        </div>

                        {/* CTA Button */}
                        <Link 
                            to={courseDetailsPath} 
                            className={`
                                px-5 py-2.5 rounded-lg font-semibold text-sm text-center transition-all duration-200 
                                flex items-center justify-center gap-2 whitespace-nowrap
                                ${isLocked 
                                    ? 'bg-slate-100 text-slate-400 cursor-not-allowed pointer-events-none border border-slate-200' 
                                    : `bg-slate-900 text-white hover:bg-slate-800 border border-slate-900`
                                }
                            `}
                        >
                            {buttonText}
                            {!isLocked && <ArrowRight size={14} strokeWidth={2.5} />}
                        </Link>
                    </div>
                </div>
            </div>
            
            {/* Bottom Progress Indicator */}
            {!isLocked && !isCompleted && (
                <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-slate-100">
                    <motion.div 
                        className={`h-full bg-gradient-to-r ${config.gradient}`}
                        initial={{ width: 0 }}
                        animate={{ width: '15%' }}
                        transition={{ duration: 0.8, delay: index * 0.1 }}
                    />
                </div>
            )}
        </motion.div>
    );
};

// --- Main Component ---
const SingleTrack = () => {
    const params = useParams();
    const trackId = params.trackId;
    const currentTrackConfig = TRACK_CONFIG[trackId];

    if (!currentTrackConfig) {
        return <Navigate to="/courses" replace />;
    }

    const { title, description, icon: HeaderIcon, courses, gradient, accentColor, glowColor } = currentTrackConfig;
    
    const isFirstCourseCompleted = false; 
    const trackProgress = isFirstCourseCompleted ? 20 : 5; 
    const completedCourses = courses.filter((_, i) => i === 0 && isFirstCourseCompleted).length;
    const totalCourses = courses.length;

    const coursesWithStatus = courses.reduce((acc, course, index) => {
        const previousCourseCompleted = index === 0 ? true : acc[index - 1].isCompleted;
        let isCompleted = false;
        let isLocked = false;

        if (index === 0) { 
            isCompleted = isFirstCourseCompleted; 
            isLocked = false; 
        } else { 
            isLocked = !previousCourseCompleted; 
            isCompleted = false; 
        }

        acc.push({ ...course, isCompleted, isLocked });
        return acc;
    }, []);

    return (
        <div className="min-h-screen bg-slate-50 py-6 px-4">
            <div className="max-w-7xl mx-auto space-y-6">
                
                {/* Breadcrumb Navigation */}
                <motion.div 
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="flex items-center gap-2 text-sm text-slate-600"
                >
                    <Link to="/courses" className="hover:text-slate-900 font-medium transition-colors">Curriculum</Link>
                    <ChevronLeft size={14} className="rotate-180" />
                    <span className="text-slate-900 font-semibold">{title}</span>
                </motion.div>

                {/* Header */}
                <motion.header 
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5 }}
                    className="bg-white rounded-lg shadow-sm border border-slate-200"
                >
                    <div className="p-8">
                        <div className="flex flex-col xl:flex-row items-start xl:items-center justify-between gap-8">
                            
                            {/* Left: Title & Description */}
                            <div className="flex-1 space-y-4">
                                <div className="flex items-center gap-4">
                                    {HeaderIcon && (
                                        <div className={`w-14 h-14 rounded-lg bg-gradient-to-br ${gradient} flex items-center justify-center shadow-md`}>
                                            <HeaderIcon size={28} className="text-white" strokeWidth={2} />
                                        </div>
                                    )}
                                    <div>
                                        <h1 className="text-3xl md:text-4xl font-bold text-slate-900 leading-tight">
                                            {title}
                                        </h1>
                                        <p className="text-sm text-slate-500 mt-1 font-medium">
                                            Professional Learning Track
                                        </p>
                                    </div>
                                </div>
                                
                                <p className="text-base text-slate-600 leading-relaxed max-w-3xl">
                                    {description}
                                </p>
                            </div>
                            
                            {/* Right: Stats Grid */}
                            <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-3 gap-4 xl:min-w-[400px]">
                                {/* Progress Card */}
                                <div className="col-span-2 sm:col-span-3 xl:col-span-3 p-5 bg-slate-50 rounded-lg border border-slate-200">
                                    <div className="flex items-center justify-between mb-3">
                                        <p className="text-xs font-bold text-slate-500 uppercase tracking-wider">Overall Progress</p>
                                        <p className={`text-2xl font-bold bg-gradient-to-r ${gradient} bg-clip-text text-transparent`}>
                                            {trackProgress}%
                                        </p>
                                    </div>
                                    <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                                        <motion.div 
                                            className={`h-full bg-gradient-to-r ${gradient} rounded-full`}
                                            initial={{ width: 0 }}
                                            animate={{ width: `${trackProgress}%` }}
                                            transition={{ duration: 1, delay: 0.3, ease: "easeOut" }}
                                        />
                                    </div>
                                </div>
                                
                                {/* Modules Completed */}
                                <div className="p-4 bg-white rounded-lg border border-slate-200">
                                    <div className="flex items-center gap-2 text-slate-600 mb-1">
                                        <Target size={14} />
                                        <p className="text-[10px] font-bold uppercase tracking-wider">Completed</p>
                                    </div>
                                    <p className="text-2xl font-bold text-slate-900">{completedCourses}/{totalCourses}</p>
                                </div>
                                
                                {/* Estimated Time */}
                                <div className="p-4 bg-white rounded-lg border border-slate-200">
                                    <div className="flex items-center gap-2 text-slate-600 mb-1">
                                        <Clock size={14} />
                                        <p className="text-[10px] font-bold uppercase tracking-wider">Total Time</p>
                                    </div>
                                    <p className="text-2xl font-bold text-slate-900">12h</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </motion.header>
                
                {/* Course List */}
                <div className="space-y-5">
                    <div className="flex items-center justify-between">
                        <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2.5">
                            <div className="w-1 h-6 bg-gradient-to-b from-indigo-600 to-indigo-700 rounded-full"></div>
                            Learning Modules
                        </h2>
                        <Link 
                            to="/courses" 
                            className="group flex items-center gap-2 text-sm font-semibold text-slate-600 hover:text-slate-900 transition-colors px-3 py-1.5 rounded-md hover:bg-slate-100"
                        >
                            <ChevronLeft size={14} className="group-hover:-translate-x-0.5 transition-transform" strokeWidth={2.5} /> 
                            Back to Overview
                        </Link>
                    </div>
                    
                    <motion.div 
                        variants={containerVariants}
                        initial="hidden"
                        animate="visible"
                        className="space-y-4"
                    >
                        {coursesWithStatus.map((course, index) => (
                            <TrackCourseCard 
                                key={course.id} 
                                course={course} 
                                index={index}
                                isCompleted={course.isCompleted}
                                isLocked={course.isLocked}
                                trackId={trackId}
                                config={currentTrackConfig}
                            />
                        ))}
                    </motion.div>
                </div>
            </div>
        </div>
    );
};

export default SingleTrack;