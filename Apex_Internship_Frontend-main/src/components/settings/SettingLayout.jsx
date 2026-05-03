import React from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { 
  User, 
  Settings, 
  CreditCard, 
  HelpCircle, 
  Award 
} from 'lucide-react';
import { motion } from 'framer-motion';

const SettingsLayout = () => {
  
    const links = [
    { name: 'My Profile', path: '/settings/profile', icon: <User size={18} /> },
    { name: 'My Grades', path: '/settings/grades', icon: <Award size={18} /> },
    { name: 'Account Settings', path: '/settings/account', icon: <Settings size={18} /> },
    { name: 'Billing & Plan', path: '/settings/billing', icon: <CreditCard size={18} /> },
    { name: 'Help Center', path: '/settings/help', icon: <HelpCircle size={18} /> },
  ];

  return (
    // Added 'mt-8' here to push the content down from the navbar
    <div className="max-w-6xl mx-auto space-y-8 mt-8">
      {/* Header */}
      <div className="border-b border-slate-200 pb-6">
        <h1 className="text-3xl font-black text-slate-900">User Settings</h1>
        <p className="text-slate-500 mt-1">Manage your profile, preferences, and internship progress.</p>
      </div>
      
      <div className="flex flex-col lg:flex-row gap-8 items-start">
        {/* Sidebar */}
        <aside className="w-full lg:w-64 shrink-0">
          <div className="flex flex-col gap-1">
            {links.map(link => (
              <NavLink 
                key={link.name}
                to={link.path}
                className={({ isActive }) => `
                  flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold transition-all
                  ${isActive 
                    ? 'bg-indigo-50 text-indigo-700 border border-indigo-100 shadow-sm' 
                    : 'text-slate-500 hover:bg-white hover:text-slate-900 border border-transparent'
                  }
                `}
              >
                {link.icon}
                {link.name}
              </NavLink>
            ))}
          </div>
        </aside>

        {/* Content Area */}
        <motion.div 
          className="flex-1 w-full"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <Outlet /> 
        </motion.div>
      </div>
    </div>
  );
};

export default SettingsLayout;