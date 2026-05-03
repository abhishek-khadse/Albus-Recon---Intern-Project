import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Shield, Eye, FileText, Lock, Database, Cookie, Mail } from 'lucide-react';

const PrivacyPolicy = () => {
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
            <div className="p-3 bg-green-100 rounded-lg">
              <Shield className="w-6 h-6 text-green-600" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-slate-900">Privacy Policy</h1>
              <p className="text-slate-600">Last updated: November 28, 2025</p>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="prose prose-slate max-w-none space-y-8">
          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Eye className="w-5 h-5 text-green-600" />
              1. Information We Collect
            </h2>
            <div className="space-y-3 text-slate-700">
              <p>We collect minimal information necessary to provide our Web3 authentication service:</p>
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Wallet Address:</strong> Public blockchain wallet address for authentication</li>
                <li><strong>Authentication Tokens:</strong> JWT tokens for session management</li>
                <li><strong>Usage Data:</strong> Anonymous usage patterns and analytics</li>
                <li><strong>Browser Data:</strong> Browser type, language, and timezone for service optimization</li>
              </ul>
              <p className="text-sm text-slate-600 bg-blue-50 p-3 rounded">
                We never collect private keys, seed phrases, or financial information.
              </p>
            </div>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Database className="w-5 h-5 text-green-600" />
              2. How We Use Your Information
            </h2>
            <div className="space-y-3 text-slate-700">
              <p>Your information is used exclusively for:</p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Authenticating your identity via Web3 wallet signatures</li>
                <li>Maintaining your session and preferences</li>
                <li>Providing customer support when requested</li>
                <li>Improving our service through anonymous analytics</li>
                <li>Ensuring platform security and preventing fraud</li>
              </ul>
            </div>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Cookie className="w-5 h-5 text-green-600" />
              3. Cookies and Local Storage
            </h2>
            <div className="space-y-3 text-slate-700">
              <p>We use browser storage for:</p>
              <ul className="list-disc pl-6 space-y-2">
                <li><strong>Session Storage:</strong> JWT tokens for active sessions</li>
                <li><strong>Local Storage:</strong> User preferences and settings</li>
                <li><strong>Cookies:</strong> Essential functionality and analytics</li>
              </ul>
              <p className="text-sm text-slate-600">
                All stored data is encrypted and accessible only to your browser session.
              </p>
            </div>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-green-600" />
              4. Data Security
            </h2>
            <div className="space-y-3 text-slate-700">
              <p>We implement multiple security measures:</p>
              <ul className="list-disc pl-6 space-y-2">
                <li>End-to-end encryption for all data transmissions</li>
                <li>Secure token storage with expiration</li>
                <li>Regular security audits and penetration testing</li>
                <li>Compliance with Web3 security best practices</li>
                <li>No storage of sensitive blockchain data</li>
              </ul>
            </div>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Lock className="w-5 h-5 text-green-600" />
              5. Data Sharing and Third Parties
            </h2>
            <div className="space-y-3 text-slate-700">
              <p>We do not sell, rent, or share your personal data with third parties. We only share:</p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Anonymous, aggregated analytics with service providers</li>
                <li>Data required by law enforcement or legal process</li>
                <li>Information necessary to prevent fraud or security threats</li>
              </ul>
            </div>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4">6. Your Rights and Choices</h2>
            <div className="space-y-3 text-slate-700">
              <p>You have the right to:</p>
              <ul className="list-disc pl-6 space-y-2">
                <li>Access your stored data at any time</li>
                <li>Request deletion of your account and data</li>
                <li>Opt-out of analytics tracking</li>
                <li>Export your data in portable format</li>
                <li>Revoke authentication tokens</li>
              </ul>
            </div>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4">7. Blockchain Transparency</h2>
            <p className="text-slate-700">
              As a Web3 platform, we believe in transparency. Your wallet address and on-chain 
              interactions are publicly visible on the blockchain. We only use this information 
              for authentication purposes and never link it to additional personal data without your consent.
            </p>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4">8. International Data Transfers</h2>
            <p className="text-slate-700">
              Your data may be processed and stored on servers in different countries. 
              We ensure appropriate safeguards are in place to protect your data regardless of location.
            </p>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4">9. Children's Privacy</h2>
            <p className="text-slate-700">
              Our service is not intended for children under 13. We do not knowingly collect 
              personal information from children under 13. If we become aware of such collection, 
              we will take immediate steps to delete this information.
            </p>
          </section>

          <section className="bg-white p-6 rounded-lg border border-slate-200">
            <h2 className="text-xl font-semibold text-slate-900 mb-4">10. Changes to This Policy</h2>
            <p className="text-slate-700">
              We may update this privacy policy from time to time. We will notify users of 
              significant changes via in-app notifications or email. Your continued use 
              of the service constitutes acceptance of any changes.
            </p>
          </section>
        </div>

        {/* Contact Section */}
        <div className="mt-12 p-6 bg-blue-50 rounded-lg border border-blue-200">
          <div className="flex items-start gap-3">
            <Mail className="w-5 h-5 text-blue-600 mt-1" />
            <div>
              <h3 className="font-semibold text-blue-900 mb-2">Privacy Questions?</h3>
              <p className="text-blue-800 text-sm mb-3">
                If you have questions about this privacy policy or want to exercise your rights, 
                please contact our privacy team.
              </p>
              <p className="text-blue-700 font-medium">privacy@novafi.io</p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-12 pt-8 border-t border-slate-200">
          <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
            <p className="text-slate-600 text-sm">
              Your privacy is important to us. We're committed to protecting your data.
            </p>
            <div className="flex gap-4">
              <Link 
                to="/terms" 
                className="text-blue-600 hover:text-blue-700 text-sm font-medium"
              >
                Terms of Service
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

export default PrivacyPolicy;
