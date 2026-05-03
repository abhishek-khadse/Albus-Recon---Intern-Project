import React from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Shield, 
  BookOpen, 
  Video, 
  Users, 
  LogOut,
  Settings,
  BarChart3,
  FileText,
  Database
} from 'lucide-react';
import { useAdminAuth } from '../../contexts/AdminAuthContext';

const SimpleAdminDashboard = () => {
  const navigate = useNavigate();
  const { adminLogout, isAdminAuthenticated } = useAdminAuth();

  // Debug: Show current auth state
  console.log('SimpleAdminDashboard - Current auth state:', isAdminAuthenticated);
  console.log('SimpleAdminDashboard - adminLogout function:', typeof adminLogout);

  const handleLogout = () => {
    console.log('SimpleAdminDashboard - Logout button clicked');
    
    try {
      const result = adminLogout();
      console.log('SimpleAdminDashboard - adminLogout result:', result);
      
      // Always navigate, even if logout fails
      console.log('SimpleAdminDashboard - Navigating to admin login');
      navigate('/admin/login');
    } catch (error) {
      console.error('SimpleAdminDashboard - Logout error:', error);
      // Force navigation even if there's an error
      navigate('/admin/login');
    }
  };

  const handleTestLogout = () => {
    console.log('SimpleAdminDashboard - Test logout clicked');
    try {
      localStorage.removeItem('adminAuth');
      console.log('SimpleAdminDashboard - Direct localStorage removal completed');
      navigate('/admin/login');
    } catch (error) {
      console.error('SimpleAdminDashboard - Test logout error:', error);
    }
  };

  const adminCards = [
    {
      title: 'Manage Courses',
      description: 'Create, edit, and organize course content',
      icon: BookOpen,
      color: 'bg-blue-600',
      hoverColor: 'hover:bg-blue-700'
    },
    {
      title: 'Manage Videos',
      description: 'Upload and manage video content',
      icon: Video,
      color: 'bg-purple-600',
      hoverColor: 'hover:bg-purple-700'
    },
    {
      title: 'Manage Users',
      description: 'View and manage user accounts',
      icon: Users,
      color: 'bg-green-600',
      hoverColor: 'hover:bg-green-700'
    }
  ];

  const quickStats = [
    { label: 'Total Courses', value: '12', icon: BookOpen },
    { label: 'Total Videos', value: '48', icon: Video },
    { label: 'Total Users', value: '1,247', icon: Users },
    { label: 'Active Sessions', value: '89', icon: BarChart3 }
  ];

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-indigo-600 rounded-lg">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">Admin Panel</h1>
                <p className="text-xs text-slate-400">ACS Administration Dashboard</p>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <button className="p-2 text-slate-400 hover:text-white hover:bg-slate-700 rounded-lg transition-colors">
                <Settings className="w-5 h-5" />
              </button>
              <button 
                onClick={handleTestLogout}
                className="flex items-center gap-2 px-3 py-2 text-amber-300 hover:text-amber-200 hover:bg-amber-900/30 rounded-lg transition-colors text-sm"
                type="button"
              >
                <span>Test Logout</span>
              </button>
              <button 
                onClick={handleLogout}
                className="flex items-center gap-2 px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-700 rounded-lg transition-colors"
                type="button"
              >
                <LogOut className="w-4 h-4" />
                <span className="text-sm">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Welcome Section */}
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-white mb-2">Welcome to Admin Panel</h2>
          <p className="text-slate-400">Manage your ACS platform from here</p>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {quickStats.map((stat, index) => (
            <div key={index} className="bg-slate-800 border border-slate-700 rounded-lg p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-slate-400">{stat.label}</p>
                  <p className="text-2xl font-bold text-white mt-1">{stat.value}</p>
                </div>
                <div className="p-3 bg-slate-700 rounded-lg">
                  <stat.icon className="w-6 h-6 text-indigo-400" />
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Management Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          {adminCards.map((card, index) => (
            <div 
              key={index}
              className="bg-slate-800 border border-slate-700 rounded-lg p-6 hover:border-slate-600 transition-all cursor-pointer group"
            >
              <div className="flex items-center gap-4 mb-4">
                <div className={`p-3 ${card.color} ${card.hoverColor} rounded-lg transition-colors`}>
                  <card.icon className="w-6 h-6 text-white" />
                </div>
                <h3 className="text-lg font-semibold text-white group-hover:text-indigo-400 transition-colors">
                  {card.title}
                </h3>
              </div>
              <p className="text-slate-400 text-sm leading-relaxed">
                {card.description}
              </p>
              <div className="mt-4">
                <button className={`text-indigo-400 hover:text-indigo-300 text-sm font-medium flex items-center gap-1 group-hover:gap-2 transition-all`}>
                  Manage →
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Additional Admin Sections */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Activity */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <FileText className="w-5 h-5 text-indigo-400" />
              Recent Activity
            </h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between py-2 border-b border-slate-700">
                <span className="text-sm text-slate-300">New user registration</span>
                <span className="text-xs text-slate-500">2 minutes ago</span>
              </div>
              <div className="flex items-center justify-between py-2 border-b border-slate-700">
                <span className="text-sm text-slate-300">Course updated</span>
                <span className="text-xs text-slate-500">15 minutes ago</span>
              </div>
              <div className="flex items-center justify-between py-2">
                <span className="text-sm text-slate-300">Video uploaded</span>
                <span className="text-xs text-slate-500">1 hour ago</span>
              </div>
            </div>
          </div>

          {/* System Status */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Database className="w-5 h-5 text-indigo-400" />
              System Status
            </h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-300">Database</span>
                <span className="px-2 py-1 bg-green-900/30 text-green-400 text-xs font-medium rounded">Online</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-300">API Server</span>
                <span className="px-2 py-1 bg-green-900/30 text-green-400 text-xs font-medium rounded">Online</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-300">Storage</span>
                <span className="px-2 py-1 bg-amber-900/30 text-amber-400 text-xs font-medium rounded">78% Used</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default SimpleAdminDashboard;
