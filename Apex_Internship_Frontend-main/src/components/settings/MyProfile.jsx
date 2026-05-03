import React, { useState, useEffect } from 'react';
import { 
  Mail, 
  Briefcase, 
  Award,
  User,
  Calendar,
  MapPin,
  Shield,
  Zap,
  Loader2,
  Edit3,
  Save,
  X
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../common/Toast';

const MyProfile = () => {
  const { user, apiRequest } = useAuth();
  const { showSuccess, showError } = useToast();
  
  const [isLoading, setIsLoading] = useState(true);
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [profileData, setProfileData] = useState({
    first_name: '',
    last_name: '',
    email: '',
    phone: '',
    bio: '',
    location: '',
    role: '',
    track: '',
    join_date: '',
    avatar_url: null
  });
  
  const [stats, setStats] = useState({
    completed_courses: 0,
    points_earned: 0,
    certifications: 0,
    overall_progress: 0
  });

  const [skills, setSkills] = useState([]);

  // --- DATA FETCHING ---
  useEffect(() => {
    const fetchProfileData = async () => {
      try {
        setIsLoading(true);
        
        // Fetch profile data
        const profile = await apiRequest('/profile');
        setProfileData({
          first_name: profile.first_name || '',
          last_name: profile.last_name || '',
          email: profile.email || '',
          phone: profile.phone || '',
          bio: profile.bio || '',
          location: profile.location || '',
          role: profile.role || 'Security Intern',
          track: profile.track || 'Web Security Track',
          join_date: profile.join_date || '',
          avatar_url: profile.avatar_url || null
        });

        // Fetch stats
        const profileStats = await apiRequest('/profile/stats');
        setStats(profileStats);

        // Fetch skills
        const profileSkills = await apiRequest('/profile/skills');
        setSkills(profileSkills || []);
        
      } catch (err) {
        console.error('Profile fetch error:', err);
        showError('Profile Error', 'Failed to load profile data');
      } finally {
        setIsLoading(false);
      }
    };

    if (user) {
      fetchProfileData();
    }
  }, [user, apiRequest, showError]);

  // --- HANDLERS ---
  const handleEdit = () => {
    setIsEditing(true);
  };

  const handleCancel = () => {
    setIsEditing(false);
    // Reset to original data
    fetchProfileData();
  };

  const handleSave = async () => {
    try {
      setIsSaving(true);
      
      await apiRequest('/profile', {
        method: 'PUT',
        body: JSON.stringify(profileData)
      });
      
      setIsEditing(false);
      showSuccess('Profile Updated', 'Your profile has been successfully updated');
      
    } catch (err) {
      console.error('Profile save error:', err);
      showError('Save Error', 'Failed to update profile');
    } finally {
      setIsSaving(false);
    }
  };

  const handleInputChange = (field, value) => {
    setProfileData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  // --- LOADING STATE ---
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 animate-spin text-indigo-600" />
          <span className="text-slate-600">Loading profile...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* --- PROFILE HEADER SECTION --- */}
      <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
        
        {/* Cover Image with Pattern */}
        <div className="relative h-40 w-full bg-gradient-to-r from-indigo-600 via-indigo-700 to-slate-900 overflow-hidden">
          <div className="absolute inset-0 opacity-10">
            <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')]"></div>
          </div>
          <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black/20"></div>
          
          {/* Edit Button */}
          <div className="absolute top-4 right-4">
            {!isEditing ? (
              <button
                onClick={handleEdit}
                className="bg-white/20 backdrop-blur-sm text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-white/30 transition-all flex items-center gap-2"
              >
                <Edit3 size={16} />
                Edit Profile
              </button>
            ) : (
              <div className="flex gap-2">
                <button
                  onClick={handleCancel}
                  className="bg-white/20 backdrop-blur-sm text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-white/30 transition-all flex items-center gap-2"
                >
                  <X size={16} />
                  Cancel
                </button>
                <button
                  onClick={handleSave}
                  disabled={isSaving}
                  className="bg-emerald-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-emerald-700 transition-all flex items-center gap-2 disabled:opacity-50"
                >
                  <Save size={16} />
                  {isSaving ? 'Saving...' : 'Save'}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Profile Content */}
        <div className="px-6 md:px-10 pb-8">
          <div className="relative flex flex-col items-center -mt-16 mb-6">
            
            {/* Avatar */}
            <div className="relative shrink-0 mb-4">
              <div className="w-32 h-32 rounded-2xl ring-4 ring-white bg-white shadow-xl overflow-hidden">
                {profileData.avatar_url ? (
                  <img 
                    src={profileData.avatar_url} 
                    alt="Profile" 
                    className="w-full h-full object-cover" 
                  />
                ) : (
                  <div className="w-full h-full bg-gradient-to-br from-indigo-500 to-indigo-600 flex items-center justify-center text-white text-3xl font-bold">
                    {profileData.first_name?.[0]}{profileData.last_name?.[0]}
                  </div>
                )}
              </div>
              <div className="absolute bottom-2 right-2 w-8 h-8 bg-emerald-500 rounded-full border-4 border-white flex items-center justify-center">
                <Shield size={16} className="text-white" />
              </div>
            </div>

            {/* Name & Info */}
            <div className="text-center">
              <h1 className="text-2xl font-bold text-slate-900 tracking-tight mb-2">
                {profileData.first_name} {profileData.last_name}
              </h1>

              <span className="inline-flex items-center gap-1.5 text-indigo-600 font-semibold bg-indigo-50 px-3 py-1.5 rounded-lg text-sm border border-indigo-100 mb-3">
                <Briefcase size={15} />
                {profileData.role}
              </span>
              
              <p className="text-slate-600 font-medium mb-4">{profileData.track}</p>
              
              {profileData.location && (
                <div className="flex items-center justify-center gap-1.5 text-slate-500 text-sm mb-2">
                  <MapPin size={14} />
                  {profileData.location}
                </div>
              )}
              
              {profileData.join_date && (
                <div className="flex items-center justify-center gap-1.5 text-slate-500 text-sm">
                  <Calendar size={14} />
                  Joined {new Date(profileData.join_date).toLocaleDateString()}
                </div>
              )}
            </div>
          </div>

          {/* Stats Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-6 border-t border-slate-100">
            <div className="text-center p-4 bg-gradient-to-br from-indigo-50 to-transparent rounded-xl border border-indigo-100/50">
              <div className="text-2xl font-bold text-slate-900">{stats.completed_courses}</div>
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mt-1">Completed Courses</div>
            </div>
            <div className="text-center p-4 bg-gradient-to-br from-emerald-50 to-transparent rounded-xl border border-emerald-100/50">
              <div className="text-2xl font-bold text-slate-900">{stats.points_earned.toLocaleString()}</div>
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mt-1">Points Earned</div>
            </div>
            <div className="text-center p-4 bg-gradient-to-br from-violet-50 to-transparent rounded-xl border border-violet-100/50">
              <div className="text-2xl font-bold text-slate-900">{stats.certifications}</div>
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mt-1">Certifications</div>
            </div>
            <div className="text-center p-4 bg-gradient-to-br from-amber-50 to-transparent rounded-xl border border-amber-100/50">
              <div className="text-2xl font-bold text-slate-900">{stats.overall_progress}%</div>
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mt-1">Overall Progress</div>
            </div>
          </div>
        </div>
      </div>

      {/* --- PERSONAL INFO --- */}
      <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
        <div className="px-6 md:px-10 py-6 border-b border-slate-100 flex justify-between items-center bg-gradient-to-r from-slate-50 to-transparent">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <User size={20} className="text-indigo-600" />
            Personal Information
          </h3>
          <span className={`text-xs font-bold uppercase px-3 py-1.5 rounded-lg border ${
            isEditing 
              ? 'bg-amber-50 text-amber-700 border-amber-200' 
              : 'bg-slate-100 text-slate-500 border-slate-200'
          }`}>
            {isEditing ? 'Editing' : 'Read Only'}
          </span>
        </div>
        
        <div className="p-6 md:p-10">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

            {/* First Name */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">First Name</label>
              <input 
                type="text" 
                value={profileData.first_name}
                onChange={(e) => handleInputChange('first_name', e.target.value)}
                readOnly={!isEditing}
                className={`w-full px-4 py-3.5 rounded-xl text-sm font-semibold transition-all focus:outline-none focus:ring-2 ${
                  isEditing 
                    ? 'bg-white border border-slate-200 text-slate-900 focus:ring-indigo-500 focus:border-indigo-500' 
                    : 'bg-slate-50 border border-slate-200 text-slate-700 cursor-not-allowed focus:ring-slate-200'
                }`}
              />
            </div>

            {/* Last Name */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Last Name</label>
              <input 
                type="text" 
                value={profileData.last_name}
                onChange={(e) => handleInputChange('last_name', e.target.value)}
                readOnly={!isEditing}
                className={`w-full px-4 py-3.5 rounded-xl text-sm font-semibold transition-all focus:outline-none focus:ring-2 ${
                  isEditing 
                    ? 'bg-white border border-slate-200 text-slate-900 focus:ring-indigo-500 focus:border-indigo-500' 
                    : 'bg-slate-50 border border-slate-200 text-slate-700 cursor-not-allowed focus:ring-slate-200'
                }`}
              />
            </div>

            {/* Email */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Email Address</label>
              <div className="relative">
                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                <input 
                  type="email" 
                  value={profileData.email}
                  onChange={(e) => handleInputChange('email', e.target.value)}
                  readOnly={!isEditing}
                  className={`w-full pl-12 pr-4 py-3.5 rounded-xl text-sm font-semibold transition-all focus:outline-none focus:ring-2 ${
                    isEditing 
                      ? 'bg-white border border-slate-200 text-slate-900 focus:ring-indigo-500 focus:border-indigo-500' 
                      : 'bg-slate-50 border border-slate-200 text-slate-700 cursor-not-allowed focus:ring-slate-200'
                  }`}
                />
              </div>
            </div>

            {/* Phone */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Phone Number</label>
              <input 
                type="tel" 
                value={profileData.phone}
                onChange={(e) => handleInputChange('phone', e.target.value)}
                readOnly={!isEditing}
                className={`w-full px-4 py-3.5 rounded-xl text-sm font-semibold transition-all focus:outline-none focus:ring-2 ${
                  isEditing 
                    ? 'bg-white border border-slate-200 text-slate-900 focus:ring-indigo-500 focus:border-indigo-500' 
                    : 'bg-slate-50 border border-slate-200 text-slate-700 cursor-not-allowed focus:ring-slate-200'
                }`}
              />
            </div>

            {/* Location */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Location</label>
              <input 
                type="text" 
                value={profileData.location}
                onChange={(e) => handleInputChange('location', e.target.value)}
                readOnly={!isEditing}
                placeholder="City, Country"
                className={`w-full px-4 py-3.5 rounded-xl text-sm font-semibold transition-all focus:outline-none focus:ring-2 ${
                  isEditing 
                    ? 'bg-white border border-slate-200 text-slate-900 focus:ring-indigo-500 focus:border-indigo-500' 
                    : 'bg-slate-50 border border-slate-200 text-slate-700 cursor-not-allowed focus:ring-slate-200'
                }`}
              />
            </div>

            {/* Bio */}
            <div className="space-y-2 md:col-span-2">
              <label className="text-xs font-bold text-slate-500 uppercase tracking-wider ml-1">Bio</label>
              <textarea 
                rows="4"
                value={profileData.bio}
                onChange={(e) => handleInputChange('bio', e.target.value)}
                readOnly={!isEditing}
                placeholder="Tell us about yourself..."
                className={`w-full p-4 rounded-xl text-sm font-medium leading-relaxed transition-all resize-none focus:outline-none focus:ring-2 ${
                  isEditing 
                    ? 'bg-white border border-slate-200 text-slate-900 focus:ring-indigo-500 focus:border-indigo-500' 
                    : 'bg-slate-50 border border-slate-200 text-slate-700 cursor-not-allowed focus:ring-slate-200'
                }`}
              />
            </div>

          </div>
        </div>
      </div>

      {/* --- SKILLS & EXPERTISE --- */}
      <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
        <div className="px-6 py-5 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
          <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
            <Zap size={20} className="text-indigo-600" />
            Skills & Expertise
          </h3>
        </div>
        <div className="p-6">
          {skills.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {skills.map((skill) => (
                <span key={skill.id} className="px-3 py-1.5 bg-indigo-50 text-indigo-700 text-xs font-semibold rounded-lg border border-indigo-100">
                  {skill.name}
                </span>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <Zap className="w-12 h-12 text-slate-300 mx-auto mb-3" />
              <p className="text-slate-500">No skills added yet</p>
            </div>
          )}
        </div>
      </div>

    </div>
  );
};

export default MyProfile;
