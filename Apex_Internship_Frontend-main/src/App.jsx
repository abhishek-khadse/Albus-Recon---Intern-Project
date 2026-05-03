import React from 'react';
import { BrowserRouter as Router, Routes, Route, Outlet, Navigate } from 'react-router-dom';

// Components
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import { ToastProvider } from './components/common/Toast';
import ErrorBoundary from './components/common/ErrorBoundary';
import NetworkStatus from './components/common/NetworkStatus';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import ProtectedRoute from './components/ProtectedRoute';

// Auth Pages
import AuthSelectorFixed from './components/AuthSelectorFixed';

// Legal Pages
import TermsOfService from './components/TermsOfService';
import PrivacyPolicy from './components/PrivacyPolicy';

// Admin Components (Separate System)
import AdminLogin from './components/admin/AdminLogin';
import AdminRoute from './components/admin/AdminRoute';
import SimpleAdminDashboard from './components/admin/SimpleAdminDashboard';
import { AdminAuthProvider } from './contexts/AdminAuthContext';

// Main Pages
import Dashboard from './components/Dashboard';
import Courses from './components/Courses';
import Leaderboard from './components/Leaderboard';
import Challenges from './components/Challenges';
import CourseDetail from './components/CoursesDetails';

// Track & Lesson Imports
import TrackWrapper from './components/TrackWrapper';
import LessonPage from './components/LessonPage';

// Settings
import SettingsLayout from './components/settings/SettingLayout';
import MyProfile from './components/settings/MyProfile';
import MyGrades from './components/settings/MyGrades';
import AccountSettings from './components/settings/AccountSettings';
import Billing from './components/settings/Billing';
import HelpCenter from './components/settings/HelpCenter';

// Layout
const AppLayout = () => {
  const { user, logout } = useAuth();

  return (
    <div className="bg-slate-50 dark:bg-slate-900 min-h-screen font-sans text-slate-900 dark:text-slate-100 flex flex-col">
      <Navbar onLogout={logout} user={user} />
      <main className="flex-grow pt-28 pb-12 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full animate-in fade-in slide-in-from-bottom-4 duration-700">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
};

function App() {
  return (
    <ToastProvider>
      <ThemeProvider>
        <ErrorBoundary>
          <NetworkStatus />
          <Router>
            <AuthProvider>
            <Routes>
            {/* Public Legal Pages */}
            <Route path="/terms" element={<TermsOfService />} />
            <Route path="/privacy" element={<PrivacyPolicy />} />

            {/* Auth Routes */}
            <Route path="/" element={<AuthSelectorFixed />} />

            {/* Admin Routes (Separate System) */}
            <Route path="/admin" element={
              <AdminAuthProvider>
                <Routes>
                  <Route path="login" element={<AdminLogin />} />
                  <Route path="/" element={
                    <AdminRoute>
                      <SimpleAdminDashboard />
                    </AdminRoute>
                  } />
                </Routes>
              </AdminAuthProvider>
            } />

            {/* Protected Main App Routes */}
            <Route element={<ProtectedRoute />}>
              <Route element={<AppLayout />}>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/courses" element={<Courses />} />
                
                {/* --- STANDARD COURSE DETAILS --- */}
                <Route path="/courses/:id" element={<CourseDetail />} />

                {/* --- TRACK ROUTES --- */}
                <Route path="/track/:trackId" element={<TrackWrapper />} />
                <Route path="/track/:trackId/courses/:id" element={<CourseDetail />} />

                {/* --- LESSON ROUTES --- */}
                <Route path="/lesson/:lessonId" element={<LessonPage />} />
                <Route path="/track/:trackId/lesson/:lessonId" element={<LessonPage />} />

                <Route path="/leaderboard" element={<Leaderboard />} />
                <Route path="/challenges" element={<Challenges />} />
                
                {/* --- SETTINGS ROUTES --- */}
                <Route path="/settings" element={<SettingsLayout />}>
                  <Route index element={<Navigate to="profile" replace />} />
                  <Route path="profile" element={<MyProfile />} />
                  <Route path="grades" element={<MyGrades />} />
                  <Route path="account" element={<AccountSettings />} />
                  <Route path="billing" element={<Billing />} />
                  <Route path="help" element={<HelpCenter />} />
                </Route>
              </Route>
            </Route>

            {/* Fallback to Dashboard for authenticated, login for unauthenticated */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AuthProvider>
          </Router>
        </ErrorBoundary>
      </ThemeProvider>
    </ToastProvider>
  );
}

export default App;