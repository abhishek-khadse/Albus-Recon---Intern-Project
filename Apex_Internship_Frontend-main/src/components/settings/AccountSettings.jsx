import React, { useState, useEffect } from 'react';
import { 
  Lock, 
  Bell, 
  Shield, 
  Mail,
  LogOut,
  AlertTriangle,
  Loader2,
  Save,
  RefreshCw
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../common/Toast';

const AccountSettings = () => {
  const { user, logout, apiRequest } = useAuth();
  const { showSuccess, showError, showInfo } = useToast();
  
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  
  const [settings, setSettings] = useState({
    email: '',
    twoFactorEnabled: false,
    emailNotifications: {
      assignments: true,
      mentor_feedback: true,
      community_mentions: false
    },
    lastPasswordChange: null
  });

  // --- DATA FETCHING ---
  useEffect(() => {
    const fetchSettings = async () => {
      try {
        setIsLoading(true);
        
        const data = await apiRequest('/settings/account');
        setSettings({
          email: data.email || '',
          twoFactorEnabled: data.two_factor_enabled || false,
          emailNotifications: {
            assignments: data.email_notifications?.assignments ?? true,
            mentor_feedback: data.email_notifications?.mentor_feedback ?? true,
            community_mentions: data.email_notifications?.community_mentions ?? false
          },
          lastPasswordChange: data.last_password_change
        });
        
      } catch (err) {
        console.error('Settings fetch error:', err);
        showError('Settings Error', 'Failed to load account settings');
      } finally {
        setIsLoading(false);
      }
    };

    if (user) {
      fetchSettings();
    }
  }, [user, apiRequest, showError]);

  // --- HANDLERS ---
  const handleSaveSettings = async () => {
    try {
      setIsSaving(true);
      
      await apiRequest('/settings/account', {
        method: 'PUT',
        body: JSON.stringify(settings)
      });
      
      showSuccess('Settings Saved', 'Your account settings have been updated');
      
    } catch (err) {
      console.error('Settings save error:', err);
      showError('Save Error', 'Failed to update settings');
    } finally {
      setIsSaving(false);
    }
  };

  const handleLogout = async () => {
    try {
      setIsLoggingOut(true);
      
      // Call backend logout endpoint to invalidate session
      await apiRequest('/auth/logout', { method: 'POST' });
      
      // Then logout on frontend
      await logout();
      
      showSuccess('Logged Out', 'You have been successfully logged out');
      
    } catch (err) {
      console.error('Logout error:', err);
      showError('Logout Error', 'Failed to logout properly');
      // Still logout on frontend even if backend call fails
      await logout();
    } finally {
      setIsLoggingOut(false);
    }
  };

  const handleEmailNotificationChange = (type, value) => {
    setSettings(prev => ({
      ...prev,
      emailNotifications: {
        ...prev.emailNotifications,
        [type]: value
      }
    }));
  };

  // --- LOADING STATE ---
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 animate-spin text-indigo-600" />
          <span className="text-slate-600">Loading account settings...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      
      {/* Email Section */}
      <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
        <div className="px-6 md:px-8 py-6 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <Mail className="text-indigo-600" size={20} />
            Email Address
          </h3>
          <p className="text-sm text-slate-500 mt-1">Your primary email for account communications</p>
        </div>
        
        <div className="p-6 md:p-8">
          <div className="flex flex-col md:flex-row gap-4 items-end">
            <div className="flex-1 w-full space-y-2">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-wider">Primary Email</label>
              <input 
                type="email" 
                value={settings.email}
                onChange={(e) => setSettings(prev => ({ ...prev, email: e.target.value }))}
                className="w-full px-4 py-3.5 bg-white border border-slate-200 rounded-xl text-sm font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all" 
              />
            </div>
            <button 
              onClick={handleSaveSettings}
              disabled={isSaving}
              className="px-6 py-3.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-sm font-bold transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {isSaving ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Save size={16} />
                  Update Email
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Security Section */}
      <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
        <div className="px-6 md:px-8 py-6 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <Shield className="text-indigo-600" size={20} />
            Security
          </h3>
          <p className="text-sm text-slate-500 mt-1">Manage your account security settings</p>
        </div>
        
        <div className="p-6 md:p-8 space-y-4">
          <div className="flex items-center justify-between p-5 border-2 border-slate-100 rounded-2xl hover:border-indigo-200 transition-colors">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-gradient-to-br from-amber-50 to-amber-100 rounded-xl flex items-center justify-center">
                <Lock className="text-amber-600" size={20} />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-900">Change Password</p>
                <p className="text-xs text-slate-500">
                  {settings.lastPasswordChange 
                    ? `Last changed ${new Date(settings.lastPasswordChange).toLocaleDateString()}`
                    : 'Never changed'
                  }
                </p>
              </div>
            </div>
            <button className="text-xs font-bold text-indigo-600 hover:text-indigo-700 transition-colors">
              Change
            </button>
          </div>

          <div className="flex items-center justify-between p-5 border-2 border-slate-100 rounded-2xl hover:border-indigo-200 transition-colors">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-gradient-to-br from-emerald-50 to-emerald-100 rounded-xl flex items-center justify-center">
                <Shield className="text-emerald-600" size={20} />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-900">Two-Factor Authentication</p>
                <p className="text-xs text-slate-500">Add an extra layer of security to your account</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className={`text-[10px] font-bold px-3 py-1.5 rounded-lg border ${
                settings.twoFactorEnabled
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-slate-50 text-slate-600 border-slate-200'
              }`}>
                {settings.twoFactorEnabled ? 'Enabled' : 'Disabled'}
              </span>
              <button className="text-xs font-bold text-indigo-600 hover:text-indigo-700 transition-colors">
                {settings.twoFactorEnabled ? 'Configure' : 'Enable'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Notifications */}
      <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
        <div className="px-6 md:px-8 py-6 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <Bell className="text-indigo-600" size={20} />
            Email Notifications
          </h3>
          <p className="text-sm text-slate-500 mt-1">Control what email notifications you receive</p>
        </div>
        
        <div className="p-6 md:p-8 space-y-4">
          <label className="flex items-center justify-between cursor-pointer p-4 border-2 border-slate-100 rounded-2xl hover:border-indigo-200 transition-colors">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-indigo-50 rounded-lg flex items-center justify-center">
                <Mail className="text-indigo-600" size={18} />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-900">New Assignments</p>
                <p className="text-xs text-slate-500">Get notified when new assignments are posted</p>
              </div>
            </div>
            <input 
              type="checkbox" 
              checked={settings.emailNotifications.assignments}
              onChange={(e) => handleEmailNotificationChange('assignments', e.target.checked)}
              className="w-5 h-5 text-indigo-600 rounded focus:ring-indigo-500 border-slate-300" 
            />
          </label>

          <label className="flex items-center justify-between cursor-pointer p-4 border-2 border-slate-100 rounded-2xl hover:border-indigo-200 transition-colors">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-emerald-50 rounded-lg flex items-center justify-center">
                <Bell className="text-emerald-600" size={18} />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-900">Mentor Feedback</p>
                <p className="text-xs text-slate-500">Receive feedback from your mentors</p>
              </div>
            </div>
            <input 
              type="checkbox" 
              checked={settings.emailNotifications.mentor_feedback}
              onChange={(e) => handleEmailNotificationChange('mentor_feedback', e.target.checked)}
              className="w-5 h-5 text-indigo-600 rounded focus:ring-indigo-500 border-slate-300" 
            />
          </label>

          <label className="flex items-center justify-between cursor-pointer p-4 border-2 border-slate-100 rounded-2xl hover:border-indigo-200 transition-colors">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-violet-50 rounded-lg flex items-center justify-center">
                <Bell className="text-violet-600" size={18} />
              </div>
              <div>
                <p className="text-sm font-medium text-slate-900">Community Mentions</p>
                <p className="text-xs text-slate-500">Get notified when mentioned in community</p>
              </div>
            </div>
            <input 
              type="checkbox" 
              checked={settings.emailNotifications.community_mentions}
              onChange={(e) => handleEmailNotificationChange('community_mentions', e.target.checked)}
              className="w-5 h-5 text-indigo-600 rounded focus:ring-indigo-500 border-slate-300" 
            />
          </label>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="bg-white border border-rose-200/60 rounded-3xl shadow-lg shadow-rose-100/50 overflow-hidden">
        <div className="px-6 md:px-8 py-6 border-b border-rose-100 bg-gradient-to-r from-rose-50 to-transparent">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <AlertTriangle className="text-rose-600" size={20} />
            Session Management
          </h3>
          <p className="text-sm text-slate-500 mt-1">Manage your active session</p>
        </div>
        
        <div className="p-6 md:p-8">
          <div className="flex items-center justify-between p-5 border-2 border-rose-100 rounded-2xl bg-rose-50/30">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-gradient-to-br from-rose-100 to-rose-200 rounded-xl flex items-center justify-center">
                <LogOut className="text-rose-600" size={20} />
              </div>
              <div>
                <p className="text-sm font-bold text-slate-900">Logout</p>
                <p className="text-xs text-slate-500">Sign out from your current session</p>
              </div>
            </div>
            <button 
              onClick={handleLogout}
              disabled={isLoggingOut}
              className="px-6 py-3 bg-rose-600 hover:bg-rose-700 text-white rounded-xl text-sm font-bold transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {isLoggingOut ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Logging out...
                </>
              ) : (
                <>
                  <LogOut size={16} />
                  Logout
                </>
              )}
            </button>
          </div>
        </div>
      </div>

    </div>
  );
};

export default AccountSettings;
