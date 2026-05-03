import React, { useState } from 'react';
import { Search, MessageSquare, Plus, Minus, ChevronRight } from 'lucide-react';

const HelpCenter = () => {
  return (
    <div className="space-y-8">
       
       {/* Search Hero */}
       <div className="bg-indigo-600 rounded-2xl p-8 text-center text-white relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-full bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-10"></div>
          <div className="relative z-10 max-w-xl mx-auto">
             <h2 className="text-2xl font-bold mb-4">How can we help you?</h2>
             <div className="relative">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={20} />
                <input type="text" placeholder="Search for answers..." className="w-full pl-12 pr-4 py-3 rounded-xl text-slate-900 font-medium focus:outline-none shadow-lg" />
             </div>
          </div>
       </div>

       {/* FAQ Section */}
       <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="space-y-4">
             <h3 className="text-lg font-bold text-slate-900 mb-4">Common Questions</h3>
             <FaqItem question="How do I reset my password?" />
             <FaqItem question="Where can I find my certificate?" />
             <FaqItem question="How to access the VPN lab?" />
             <FaqItem question="Can I change my internship track?" />
          </div>

          {/* Contact Card */}
          <div className="bg-white border border-slate-200 rounded-2xl p-8 shadow-sm h-fit">
             <h3 className="text-lg font-bold text-slate-900 mb-2">Still need help?</h3>
             <p className="text-sm text-slate-500 mb-6">Our support team is available Mon-Fri, 9am - 5pm.</p>
             
             <form className="space-y-4">
                <div className="space-y-1">
                   <label className="text-xs font-bold text-slate-500 uppercase">Subject</label>
                   <select className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-sm font-medium outline-none">
                      <option>Technical Issue</option>
                      <option>Billing Inquiry</option>
                      <option>Course Content</option>
                   </select>
                </div>
                <div className="space-y-1">
                   <label className="text-xs font-bold text-slate-500 uppercase">Message</label>
                   <textarea rows="3" className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-sm font-medium outline-none resize-none" placeholder="Describe your issue..."></textarea>
                </div>
                <button className="w-full py-3 bg-slate-900 text-white rounded-xl text-sm font-bold hover:bg-indigo-600 transition-colors flex items-center justify-center gap-2">
                   <MessageSquare size={16} /> Send Ticket
                </button>
             </form>
          </div>
       </div>

    </div>
  );
};

const FaqItem = ({ question }) => (
   <div className="bg-white border border-slate-200 rounded-xl p-4 flex justify-between items-center cursor-pointer hover:border-indigo-300 transition-colors group">
      <span className="text-sm font-bold text-slate-700 group-hover:text-indigo-700">{question}</span>
      <ChevronRight size={16} className="text-slate-400 group-hover:text-indigo-500" />
   </div>
);

export default HelpCenter;