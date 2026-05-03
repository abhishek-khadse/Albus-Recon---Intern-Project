import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Trophy, 
  Medal, 
  TrendingUp, 
  TrendingDown, 
  Minus, 
  Search, 
  ChevronLeft, 
  ChevronRight,
  Crown,
  Sparkles,
  Award,
  Target,
  RefreshCw,
  AlertTriangle,
  Users
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useToast } from './common/Toast';

// --- ANIMATION VARIANTS ---
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.05, delayChildren: 0.1 }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 10 },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { type: "spring", stiffness: 50, damping: 20 } 
  }
};

const Leaderboard = () => {
  const { user, apiRequest } = useAuth();
  const { showError, showSuccess } = useToast();
  
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [leaderboardData, setLeaderboardData] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const ITEMS_PER_PAGE = 10;

  // --- DATA FETCHING ---
  const fetchLeaderboardData = async (page = 1, search = '') => {
    try {
      setError(null);
      
      const params = new URLSearchParams({
        page: page.toString(),
        limit: ITEMS_PER_PAGE.toString(),
        ...(search && { search })
      });
      
      const data = await apiRequest(`/leaderboard?${params}`);
      
      // Map backend data to frontend format
      const mappedParticipants = (data.participants || []).map(participant => ({
        id: participant.wallet_address,
        name: participant.display_name,
        score: participant.total_points,
        rank: participant.rank,
        role: participant.role || 'Student',
        avatar: participant.avatar_url,
        trend: participant.trend || 'neutral',
        badges: participant.badges || []
      }));
      
      const mappedCurrentUser = data.current_user ? {
        id: data.current_user.wallet_address,
        name: data.current_user.display_name,
        score: data.current_user.total_points,
        rank: data.current_user.rank,
        role: data.current_user.role || 'Student',
        avatar: data.current_user.avatar_url,
        trend: data.current_user.trend || 'neutral',
        badges: data.current_user.badges || []
      } : null;
      
      setLeaderboardData(mappedParticipants);
      setCurrentUser(mappedCurrentUser);
      setTotalPages(Math.ceil((data.total_count || 0) / ITEMS_PER_PAGE));
      
    } catch (err) {
      console.error('Leaderboard fetch error:', err);
      // Handle different error object structures
      const errorMessage = err.message || err.msg || 'Failed to load leaderboard data';
      setError(errorMessage);
      showError('Leaderboard Error', errorMessage);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    if (user) {
      fetchLeaderboardData(currentPage, searchTerm);
    }
  }, [user, currentPage]);

  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (searchTerm) {
        // Client-side filtering since backend doesn't support search
        const filtered = leaderboardData.filter(player => 
          player.name.toLowerCase().includes(searchTerm.toLowerCase())
        );
        setLeaderboardData(filtered);
        setCurrentPage(1);
        setTotalPages(Math.ceil(filtered.length / ITEMS_PER_PAGE));
      } else {
        // Reset to original data
        fetchLeaderboardData(1, '');
      }
    }, 500);

    return () => clearTimeout(timeoutId);
  }, [searchTerm]);

  // --- HANDLERS ---
  const handleRefresh = async () => {
    setIsRefreshing(true);
    await fetchLeaderboardData(currentPage, searchTerm);
    showSuccess('Refreshed', 'Leaderboard data updated');
  };

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPage(newPage);
    }
  };

  // --- FILTERED DATA ---
  const topPerformers = leaderboardData.slice(0, 3);
  const otherParticipants = leaderboardData.slice(3);

  // --- LOADING AND ERROR STATES ---
  if (isLoading && !leaderboardData.length) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-indigo-50/30 to-slate-100 p-4 md:p-8">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-center min-h-96">
            <div className="flex flex-col items-center gap-4">
              <RefreshCw className="w-8 h-8 animate-spin text-indigo-600" />
              <span className="text-slate-600">Loading leaderboard...</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error && !leaderboardData.length) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-indigo-50/30 to-slate-100 p-4 md:p-8">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-center min-h-96">
            <div className="text-center max-w-md">
              <AlertTriangle className="w-12 h-12 text-amber-500 mx-auto mb-4" />
              <h2 className="text-xl font-semibold text-slate-900 mb-2">Failed to Load Leaderboard</h2>
              <p className="text-slate-600 mb-6">{error}</p>
              <button
                onClick={handleRefresh}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 mx-auto"
              >
                <RefreshCw className="w-4 h-4" />
                Try Again
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-indigo-50/30 to-slate-100 p-4 md:p-8">
      <motion.div 
        className="max-w-7xl mx-auto space-y-6"
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        
        {/* --- ENHANCED HEADER --- */}
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 mb-6">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-3xl font-bold text-slate-900">Leaderboard</h1>
              <span className="px-3 py-1 bg-amber-100 text-amber-700 text-xs font-bold rounded-lg border border-amber-200 flex items-center gap-1">
                <Trophy size={14} />
                Live Rankings
              </span>
            </div>
            <p className="text-slate-600 max-w-2xl">
              Track your ranking against peers. Points are awarded for completing modules, solving CTFs, and mentor reviews.
            </p>
          </div>
          
          {/* Stats Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
            <div className="bg-white border border-slate-200/60 rounded-xl p-4 shadow-lg shadow-indigo-100/50">
              <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Your Rank</p>
              {currentUser ? (
                <p className="text-2xl font-black text-indigo-600">#{currentUser.rank}</p>
              ) : (
                <div className="h-8 w-16 bg-slate-200 rounded animate-pulse"></div>
              )}
            </div>
            <div className="bg-white border border-slate-200/60 rounded-xl p-4 shadow-lg shadow-indigo-100/50">
              <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Your Points</p>
              {currentUser ? (
                <p className="text-2xl font-black text-slate-900">{currentUser.score.toLocaleString()}</p>
              ) : (
                <div className="h-8 w-16 bg-slate-200 rounded animate-pulse"></div>
              )}
            </div>
            <div className="bg-white border border-slate-200/60 rounded-xl p-4 shadow-lg shadow-indigo-100/50 col-span-2 lg:col-span-1">
              <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">To Next Rank</p>
              {currentUser?.next_rank_diff !== undefined ? (
                <p className="text-2xl font-black text-emerald-600">+{currentUser.next_rank_diff}</p>
              ) : (
                <div className="h-8 w-16 bg-slate-200 rounded animate-pulse"></div>
              )}
            </div>
          </div>
        </div>

        {/* --- TOP 3 PODIUM --- */}
        {topPerformers.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {isLoading ? (
              <>
                <TopPerformerSkeleton className="order-2 md:order-1 md:mt-8" />
                <TopPerformerSkeleton className="order-1 md:order-2" isWinner />
                <TopPerformerSkeleton className="order-3 md:order-3 md:mt-8" />
              </>
            ) : (
              <>
                {topPerformers[1] && (
                  <div className="order-2 md:order-1 md:mt-8">
                    <TopPerformerCard 
                      player={topPerformers[1]} 
                      gradient="from-slate-400 to-slate-500"
                      icon={<Medal size={24} className="text-white" />} 
                      label="2nd Place" 
                    />
                  </div>
                )}
                {topPerformers[0] && (
                  <div className="order-1 md:order-2">
                    <TopPerformerCard 
                      player={topPerformers[0]} 
                      gradient="from-amber-400 to-amber-500"
                      icon={<Crown size={28} className="text-white" />} 
                      label="1st Place" 
                      isWinner 
                    />
                  </div>
                )}
                {topPerformers[2] && (
                  <div className="order-3 md:order-3 md:mt-8">
                    <TopPerformerCard 
                      player={topPerformers[2]} 
                      gradient="from-orange-400 to-orange-500"
                      icon={<Medal size={24} className="text-white" />} 
                      label="3rd Place" 
                    />
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* --- LEADERBOARD TABLE --- */}
        <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
          
          {/* Toolbar */}
          <div className="px-6 md:px-8 py-5 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                  <Target size={20} className="text-indigo-600" />
                  All Rankings
                </h2>
                <p className="text-sm text-slate-500 mt-1">Complete ranking of all participants</p>
              </div>
              <div className="flex items-center gap-3">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                  <input 
                    type="text" 
                    placeholder="Search interns..." 
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 w-full md:w-64 transition-all"
                  />
                </div>
                <button
                  onClick={handleRefresh}
                  disabled={isRefreshing}
                  className="p-2.5 rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-white transition-all disabled:opacity-50"
                >
                  <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
                </button>
              </div>
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50">
                  <th className="px-6 md:px-8 py-4 text-center">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Rank</span>
                  </th>
                  <th className="px-6 md:px-8 py-4 text-left">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Participant</span>
                  </th>
                  <th className="px-6 py-4 text-center">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Trend</span>
                  </th>
                  <th className="px-6 md:px-8 py-4 text-right">
                    <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Total XP</span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {isLoading && !leaderboardData.length ? (
                  <>
                    <SkeletonRow />
                    <SkeletonRow />
                    <SkeletonRow />
                    <SkeletonRow />
                    <SkeletonRow />
                  </>
                ) : (
                  <>
                    {otherParticipants.map((player) => (
                      <LeaderboardRow key={player.id} player={player} isCurrentUser={currentUser?.id === player.id} />
                    ))}
                    {/* Current User (if not in current page) */}
                    {currentUser && !otherParticipants.some(p => p.id === currentUser.id) && (
                      <tr className="bg-gradient-to-r from-indigo-50 to-indigo-100/50 border-t-2 border-indigo-200">
                        <td className="px-6 md:px-8 py-5 text-center">
                          <div className="inline-flex items-center justify-center w-8 h-8 rounded-lg bg-indigo-600 text-white font-black text-sm shadow-lg">
                            {currentUser.rank}
                          </div>
                        </td>
                        <td className="px-6 md:px-8 py-5">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-indigo-600 text-white flex items-center justify-center text-sm font-bold shadow-lg border-2 border-white">
                              ME
                            </div>
                            <div>
                              <div className="font-bold text-slate-900 flex items-center gap-2">
                                {currentUser.name}
                                <span className="px-2 py-0.5 bg-indigo-600 text-white text-[10px] font-bold rounded uppercase">You</span>
                              </div>
                              <div className="text-xs text-slate-600 font-medium">{currentUser.role}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-5 text-center">
                          <TrendIcon trend={currentUser.trend} />
                        </td>
                        <td className="px-6 md:px-8 py-5 text-right">
                          <span className="font-mono font-black text-indigo-600 text-lg">
                            {currentUser.score.toLocaleString()}
                          </span>
                        </td>
                      </tr>
                    )}
                  </>
                )}
              </tbody>
            </table>
          </div>

          {/* Error State (if partial data loaded) */}
          {error && leaderboardData.length > 0 && (
            <div className="px-6 py-4 bg-amber-50 border-t border-amber-200">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-600" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-amber-900">Partial data loaded</p>
                  <p className="text-xs text-amber-700">{error}</p>
                </div>
                <button
                  onClick={handleRefresh}
                  className="text-sm font-medium text-amber-700 hover:text-amber-800"
                >
                  Retry
                </button>
              </div>
            </div>
          )}

          {/* Empty State */}
          {!isLoading && !error && leaderboardData.length === 0 && (
            <div className="px-6 py-12 text-center">
              <Users className="w-12 h-12 text-slate-400 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-slate-900 mb-2">No participants found</h3>
              <p className="text-slate-600 mb-4">
                {searchTerm ? 'No participants match your search criteria.' : 'No leaderboard data available.'}
              </p>
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="text-sm font-medium text-indigo-600 hover:text-indigo-700"
                >
                  Clear search
                </button>
              )}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="px-6 md:px-8 py-4 border-t border-slate-100 bg-slate-50/50 flex flex-col sm:flex-row items-center justify-between gap-4">
              <span className="text-xs text-slate-600 font-medium">
                Showing {((currentPage - 1) * ITEMS_PER_PAGE) + 1}-{Math.min(currentPage * ITEMS_PER_PAGE, leaderboardData.length)} of {leaderboardData.length} participants
              </span>
              <div className="flex gap-2">
                <button 
                  onClick={() => handlePageChange(currentPage - 1)}
                  disabled={currentPage === 1}
                  className="p-2 rounded-lg border border-slate-200 text-slate-400 hover:text-slate-700 hover:bg-white hover:border-slate-300 transition-all disabled:opacity-50"
                >
                  <ChevronLeft size={16} />
                </button>
                <div className="flex gap-1">
                  {Array.from({ length: Math.min(3, totalPages) }, (_, i) => {
                    const pageNum = i + 1;
                    return (
                      <button
                        key={pageNum}
                        onClick={() => handlePageChange(pageNum)}
                        className={`px-3 py-2 rounded-lg text-sm font-bold transition-all ${
                          currentPage === pageNum
                            ? 'bg-indigo-600 text-white'
                            : 'border border-slate-200 text-slate-700 hover:bg-slate-50'
                        }`}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                  {totalPages > 3 && (
                    <>
                      <span className="px-2 py-2 text-slate-400">...</span>
                      <button
                        onClick={() => handlePageChange(totalPages)}
                        className={`px-3 py-2 rounded-lg text-sm font-bold transition-all ${
                          currentPage === totalPages
                            ? 'bg-indigo-600 text-white'
                            : 'border border-slate-200 text-slate-700 hover:bg-slate-50'
                        }`}
                      >
                        {totalPages}
                      </button>
                    </>
                  )}
                </div>
                <button 
                  onClick={() => handlePageChange(currentPage + 1)}
                  disabled={currentPage === totalPages}
                  className="p-2 rounded-lg border border-slate-200 text-slate-400 hover:text-slate-700 hover:bg-white hover:border-slate-300 transition-all"
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </div>
          )}
        </div>

      </motion.div>
    </div>
  );
};

/* --- LOADING SKELETONS --- */

const TopPerformerSkeleton = ({ className, isWinner }) => (
  <div className={`bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden ${className} ${isWinner ? 'ring-2 ring-amber-200' : ''}`}>
    <div className="p-6 flex flex-col items-center text-center">
      <div className="w-12 h-12 rounded-full bg-slate-200 animate-pulse mb-4"></div>
      <div className="w-24 h-24 rounded-2xl bg-slate-200 animate-pulse mb-4 border-4 border-white shadow-lg"></div>
      <div className="h-6 w-32 bg-slate-200 rounded animate-pulse mb-2"></div>
      <div className="h-4 w-24 bg-slate-100 rounded animate-pulse mb-6"></div>
      <div className="w-full pt-4 border-t border-slate-100">
        <div className="h-5 w-20 bg-slate-200 rounded animate-pulse mx-auto"></div>
      </div>
    </div>
  </div>
);

const SkeletonRow = () => (
  <tr>
    <td className="px-6 md:px-8 py-5"><div className="h-5 w-8 mx-auto bg-slate-200 rounded animate-pulse"></div></td>
    <td className="px-6 md:px-8 py-5">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-slate-200 animate-pulse"></div>
        <div className="space-y-2">
          <div className="h-4 w-28 bg-slate-200 rounded animate-pulse"></div>
          <div className="h-3 w-20 bg-slate-100 rounded animate-pulse"></div>
        </div>
      </div>
    </td>
    <td className="px-6 py-5"><div className="h-5 w-12 mx-auto bg-slate-100 rounded animate-pulse"></div></td>
    <td className="px-6 md:px-8 py-5 text-right"><div className="h-5 w-16 ml-auto bg-slate-200 rounded animate-pulse"></div></td>
  </tr>
);

/* --- DATA COMPONENTS --- */

const TopPerformerCard = ({ player, gradient, icon, label, isWinner }) => (
  <motion.div 
    variants={itemVariants}
    whileHover={{ y: -8, scale: 1.02 }}
    className={`bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden cursor-default ${isWinner ? 'ring-2 ring-amber-200' : ''}`}
  >
    <div className="p-6 flex flex-col items-center text-center relative">
      {/* Badge Icon */}
      <div className={`w-12 h-12 rounded-full bg-gradient-to-br ${gradient} flex items-center justify-center shadow-xl mb-4 ring-4 ring-white`}>
        {icon}
      </div>
      
      {/* Avatar */}
      <div className="w-24 h-24 rounded-2xl bg-slate-100 flex items-center justify-center text-2xl font-black text-slate-400 mb-4 border-4 border-white shadow-lg">
        {player.avatar || player.name?.split(' ').map(n => n[0]).join('').toUpperCase()}
      </div>
      
      {/* Info */}
      <h3 className="font-bold text-slate-900 text-lg mb-1">{player.name}</h3>
      <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4">{player.role}</p>
      
      {/* Score Section */}
      <div className="w-full pt-4 border-t border-slate-100">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">{label}</p>
        <p className="text-2xl font-black text-slate-900">{player.score.toLocaleString()}</p>
        <p className="text-xs text-slate-500 font-medium">Experience Points</p>
      </div>
    </div>
  </motion.div>
);

const LeaderboardRow = ({ player, isCurrentUser }) => (
  <motion.tr 
    variants={itemVariants}
    className={`hover:bg-slate-50/50 transition-colors group ${
      isCurrentUser ? 'bg-gradient-to-r from-indigo-50 to-indigo-100/50 border-t-2 border-indigo-200' : ''
    }`}
  >
    <td className="px-6 md:px-8 py-5 text-center">
      <span className={`inline-flex items-center justify-center w-8 h-8 rounded-lg font-black text-sm transition-colors ${
        isCurrentUser 
          ? 'bg-indigo-600 text-white shadow-lg' 
          : 'bg-slate-100 text-slate-700 group-hover:bg-slate-200'
      }`}>
        {player.rank}
      </span>
    </td>
    <td className="px-6 md:px-8 py-5">
      <div className="flex items-center gap-3">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-sm font-bold shadow-sm ${
          isCurrentUser 
            ? 'bg-gradient-to-br from-indigo-500 to-indigo-600 text-white border-2 border-white' 
            : 'bg-gradient-to-br from-slate-200 to-slate-300 text-slate-600'
        }`}>
          {isCurrentUser ? 'ME' : (player.avatar || player.name?.split(' ').map(n => n[0]).join('').toUpperCase())}
        </div>
        <div>
          <div className="font-bold text-slate-900 text-sm flex items-center gap-2">
            {player.name}
            {isCurrentUser && (
              <span className="px-2 py-0.5 bg-indigo-600 text-white text-[10px] font-bold rounded uppercase">You</span>
            )}
          </div>
          <div className="text-xs text-slate-500 font-medium">{player.role}</div>
        </div>
      </div>
    </td>
    <td className="px-6 py-5 text-center">
      <TrendIcon trend={player.trend} />
    </td>
    <td className="px-6 md:px-8 py-5 text-right">
      <span className={`font-mono font-black text-lg ${
        isCurrentUser ? 'text-indigo-600' : 'text-slate-900'
      }`}>
        {player.score.toLocaleString()}
      </span>
    </td>
  </motion.tr>
);

const TrendIcon = ({ trend }) => {
  if (trend === 'up') return (
    <div className="inline-flex items-center gap-1.5 text-xs font-bold text-emerald-600 bg-emerald-50 px-3 py-1.5 rounded-lg border border-emerald-200">
      <TrendingUp size={14} /> +4
    </div>
  );
  if (trend === 'down') return (
    <div className="inline-flex items-center gap-1.5 text-xs font-bold text-rose-600 bg-rose-50 px-3 py-1.5 rounded-lg border border-rose-200">
      <TrendingDown size={14} /> -2
    </div>
  );
  return (
    <div className="inline-flex items-center gap-1.5 text-xs font-bold text-slate-500 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200">
      <Minus size={14} /> 0
    </div>
  );
};

export default Leaderboard;
