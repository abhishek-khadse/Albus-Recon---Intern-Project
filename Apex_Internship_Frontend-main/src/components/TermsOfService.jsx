import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Shield, Eye, FileText, Lock, Users, Mail } from 'lucide-react';

const TermsOfService = () => {
  return (
    <div className="min-h-screen bg-slate-50">
      <div className="max-w-4xl mx-auto px-4 py-12">
        {/* Header */}
        <div className="mb-8">
          <Link 
            to="/login" 
            className="inline-flex items-center gap-2 text-slate-600 hover:text-slate-900 mb-4"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Login
          </Link>
          
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-blue-100 rounded-lg">
              <FileText className="w-6 h-6 text-blue-600" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-slate-900">Terms of Service</h1>
              <p className="text-slate-600">Last updated: November 28, 2025</p>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="prose prose-slate max-w-none space-y-8">
          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-600" />
              1. Acceptance of Terms
            </h2>
            <p className="text-slate-700 leading-relaxed">
              By accessing and using NovaFi, you accept and agree to be bound by the terms and provision of this agreement. 
              If you do not agree to abide by the above, please do not use this service.
            </p>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Users className="w-5 h-5 text-blue-600" />
              2. Web3 Authentication
            </h2>
            <div className="space-y-3 text-slate-700">
              <p>
                NovaFi uses blockchain-based authentication through Web3 wallets. By using our service, you:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Grant us permission to verify your wallet address ownership</li>
                <li>Allow us to store authentication tokens securely</li>
                <li>Understand that blockchain transactions are irreversible</li>
                <li>Are responsible for securing your wallet and private keys</li>
              </ul>
              <p className="text-sm text-slate-600">
                We never have access to your private keys or funds. We only verify wallet ownership for authentication purposes.
              </p>
            </div>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Eye className="w-5 h-5 text-blue-600" />
              3. Privacy and Data Use
            </h2>
            <div className="space-y-3 text-slate-700">
              <p>
                We are committed to protecting your privacy:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>We collect only necessary information for service provision</li>
                <li>Wallet addresses are used solely for authentication and identification</li>
                <li>We do not sell or share your personal data with third parties</li>
                <li>You can request data deletion at any time</li>
              </ul>
            </div>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Lock className="w-5 h-5 text-blue-600" />
              4. Security Responsibilities
            </h2>
            <div className="space-y-3 text-slate-700">
              <p>
                As a user, you are responsible for:
              </p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Keeping your wallet secure and private keys safe</li>
                <li>Using strong wallet passwords and 2FA when available</li>
                <li>Verifying transaction details before signing</li>
                <li>Reporting security vulnerabilities to our team</li>
              </ul>
            </div>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4">5. Service Availability</h2>
            <p className="text-slate-700">
              We strive to maintain high service availability but cannot guarantee 100% uptime. 
              The service is provided "as is" without warranties of any kind.
            </p>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4">6. Limitation of Liability</h2>
            <p className="text-slate-700">
              NovaFi shall not be liable for any indirect, incidental, or consequential damages 
              arising from your use of our service, including but not limited to loss of funds or data.
            </p>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4">7. Changes to Terms</h2>
            <p className="text-slate-700">
              We reserve the right to modify these terms at any time. Changes will be effective 
              immediately upon posting. Your continued use of the service constitutes acceptance of any changes.
            </p>
          </section>
        </div>

        {/* Footer */}
        <div className="mt-12 pt-8 border-t border-slate-200">
          <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
            <p className="text-slate-600 text-sm">
              Questions about our terms? Contact us at legal@novafi.io
            </p>
            <div className="flex gap-4">
              <Link 
                to="/privacy" 
                className="text-blue-600 hover:text-blue-700 text-sm font-medium"
              >
                Privacy Policy
              </Link>
              <Link 
                to="/help" 
                className="text-blue-600 hover:text-blue-700 text-sm font-medium"
              >
                Help Center
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TermsOfService;
