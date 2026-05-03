import React from 'react';
import { 
  Github, 
  Twitter, 
  Linkedin, 
  Heart, 
  ExternalLink 
} from 'lucide-react';

// Ensure this matches your logo path
const LOGO_PATH = "/image/AlbusSecurityLogoBlack.jpg"; 

const Footer = () => {
  const currentYear = new Date().getFullYear();

  return (
    // Changed border-slate-200 to border-slate-300 for better visibility
    <footer className="bg-white border-t border-slate-300 mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-10">
          
          {/* Col 1: Brand Identity */}
          <div className="col-span-1 md:col-span-1">
            {/* Logo Link */}
            <div className="mb-4">
              <a href="#" className="inline-block">
                <img 
                  src={LOGO_PATH} 
                  alt="Albus Security Logo" 
                  className="h-12 w-auto object-contain hover:opacity-80 transition-opacity" 
                />
              </a>
            </div>
            
            {/* Description with Link */}
            <p className="text-sm font-medium text-slate-600 leading-relaxed mb-2">
              The ACS Internship is a premier educational initiative by{' '}
              <a href="#" className="font-bold hover:text-indigo-700 hover:underline transition-colors">
                Albus Security LLP
              </a>.
            </p>
            <p className="text-xs text-slate-500">
              Empowering the next generation of cybersecurity professionals.
            </p>
          </div>

          {/* Col 2: Platform Links */}
          <div>
            <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4">Platform</h4>
            <ul className="space-y-3">
              <FooterLink label="My Dashboard" href="/" />
              <FooterLink label="Browse Courses" href="/courses" />
              <FooterLink label="Mentorship" href="#" />
              <FooterLink label="Leaderboard" href="/leaderboard" />
            </ul>
          </div>

          {/* Col 3: Support */}
          <div>
            <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4">Support</h4>
            <ul className="space-y-3">
              <FooterLink label="Help Center" href="/support" />
              <FooterLink label="Report a Bug" href="/securityreport" />
              <FooterLink label="Privacy Policy" href="/privacy" />
              <FooterLink label="Terms of Service" href="/terms" />
            </ul>
          </div>

          {/* Col 4: Connect & Status */}
          <div>
            <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wider mb-4">Connect</h4>
            <div className="flex items-center gap-4 mb-6">
              <SocialIcon href="https://github.com/albussec" icon={<Github size={20} />} />
              <SocialIcon href="https://linkedin.com/company/77666396" icon={<Linkedin size={20} />} />
              <SocialIcon href="https://x.com/AniketT09523306" icon={<Twitter size={20} />} />
            </div>
            
            {/* Status Indicator */}
            <a href="#" className="inline-flex items-center gap-2 px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg hover:bg-slate-100 transition-colors group">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-600"></span>
              </span>
              <span className="text-xs font-bold text-slate-700 group-hover:text-indigo-700">Systems Operational</span>
            </a>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-slate-300 flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="text-sm font-medium text-slate-600">
            &copy; 2026 <a href="/" className="hover:text-indigo-700 hover:underline transition-colors">Albus Security LLP</a>. All rights reserved.
          </p>
          
          <div className="flex items-center gap-1.5 text-sm font-medium text-slate-600">
            <span>Designed with</span>
            <Heart size={14} className="text-rose-600 fill-rose-600" />
            <span>for</span>
            <a href="/" className="hover:text-indigo-700 hover:underline transition-colors">The ACS Project</a>
          </div>
        </div>

      </div>
    </footer>
  );
};

/* --- Sub-Components --- */

const FooterLink = ({ label, href }) => (
  <li>
    <a href={href} className="text-sm font-medium text-slate-600 hover:text-indigo-700 hover:underline transition-colors flex items-center gap-1 group">
      {label}
      <ExternalLink size={12} className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-400" />
    </a>
  </li>
);

const SocialIcon = ({ icon, href }) => (
  <a href={href} className="text-slate-500 hover:text-indigo-700 hover:bg-indigo-50 p-2 rounded-lg transition-all border border-transparent hover:border-indigo-100">
    {icon}
  </a>
);

export default Footer;