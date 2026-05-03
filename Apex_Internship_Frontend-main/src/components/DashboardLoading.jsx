import React, { useEffect, useState } from 'react';

// Ensure correct path
const LOGO_PATH = "/image/AlbusSecurityIconBlack.png"; 

const Preloader = () => {
  const [loading, setLoading] = useState(true); 
  const [shouldRender, setShouldRender] = useState(true); 
  

  const [startAnimation, setStartAnimation] = useState(false);

  useEffect(() => {

    const startTimer = setTimeout(() => setStartAnimation(true), 100);
    const exitTimer = setTimeout(() => {
      setLoading(false); 
      setTimeout(() => setShouldRender(false), 1000); 
    }, 4000);

    return () => {
      clearTimeout(startTimer);
      clearTimeout(exitTimer);
    };
  }, []);

  if (!shouldRender) return null;

  return (
    <div 
      className={`
        fixed inset-0 z-[9999] bg-white flex flex-col items-center justify-center px-4 overflow-hidden
        transition-opacity duration-1000 ease-in-out
        ${loading ? 'opacity-100' : 'opacity-0 pointer-events-none'}
      `}
    >
      

      <div 
        className={`
          relative w-20 h-20 md:w-28 md:h-28 mb-8 flex items-center justify-center
          transition-all duration-1000 ease-[cubic-bezier(0.25,1,0.5,1)]
          ${startAnimation ? 'opacity-100 translate-y-0 scale-100' : 'opacity-0 translate-y-10 scale-95'}
        `}
      >
        {/* Background Glow */}
        <div className="absolute inset-0 bg-indigo-400 rounded-full blur-2xl opacity-20 animate-pulse-slow"></div>
        
        {/* Logo Image with Gentle Float Loop */}
        <img 
          src={LOGO_PATH} 
          alt="The ACS" 
          className="relative w-full h-full object-contain drop-shadow-xl animate-float-gentle"
        />
      </div>

      {/* --- 2. MAIN TITLE (Delay 100ms) --- */}
      <div className="w-full text-center overflow-hidden">
        <h1 
          className={`
            text-xl sm:text-3xl md:text-4xl lg:text-5xl font-black text-slate-900 tracking-tight whitespace-nowrap
            transition-all duration-1000 delay-100 ease-[cubic-bezier(0.25,1,0.5,1)]
            ${startAnimation ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}
          `}
        >
          THE ACS INTERNSHIP
        </h1>
      </div>

      {/* --- 3. SUBHEADING (Delay 200ms) --- */}
      <div className="overflow-hidden mt-2">
        <p 
          className={`
            text-[10px] sm:text-xs md:text-sm font-bold text-indigo-600 tracking-[0.2em] uppercase text-center
            transition-all duration-1000 delay-200 ease-[cubic-bezier(0.25,1,0.5,1)]
            ${startAnimation ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}
          `}
        >
          An Ultimate Learning Platform
        </p>
      </div>

      {/* --- 4. LOADING BAR (Delay 300ms) --- */}
      <div 
        className={`
          mt-10 w-32 md:w-48 h-1 bg-slate-100 rounded-full overflow-hidden
          transition-all duration-1000 delay-300 ease-[cubic-bezier(0.25,1,0.5,1)]
          ${startAnimation ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}
        `}
      >
        <div className="h-full bg-gradient-to-r from-indigo-600 via-purple-500 to-indigo-600 w-full animate-data-stream"></div>
      </div>

      {/* --- 5. FOOTER (Delay 500ms) --- */}
      <div 
        className={`
          absolute bottom-8 md:bottom-12 text-center
          transition-all duration-1000 delay-500 ease-[cubic-bezier(0.25,1,0.5,1)]
          ${startAnimation ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}
        `}
      >
        <p className="text-[9px] text-black font-bold uppercase tracking-widest mb-2">
          Powered by
        </p>
        <div className="inline-flex items-center justify-center gap-2 bg-slate-50 px-3 py-1.5 rounded-full border border-slate-100 shadow-sm">
            <div className="w-1.5 h-1.5 bg-indigo-600 rounded-full animate-ping-slow"></div>
            <span className="text-[10px] md:text-xs font-bold text-slate-800 tracking-wide">
              ALBUS SECURITY LLP
            </span>
        </div>
      </div>

    </div>
  );
};

export default Preloader;