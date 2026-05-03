import React, { useState, useEffect } from 'react';
import { 
  Check, 
  Download, 
  Shield,
  CreditCard,
  Calendar,
  FileText,
  AlertCircle,
  Loader2,
  RefreshCw,
  Crown,
  Zap
} from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../common/Toast';

const Billing = () => {
  const { user, apiRequest } = useAuth();
  const { showSuccess, showError } = useToast();
  
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [subscription, setSubscription] = useState(null);
  const [invoices, setInvoices] = useState([]);
  const [paymentMethods, setPaymentMethods] = useState([]);

  // --- DATA FETCHING ---
  useEffect(() => {
    const fetchBillingData = async () => {
      try {
        setIsLoading(true);
        
        // Fetch subscription info
        const subscriptionData = await apiRequest('/billing/subscription');
        setSubscription(subscriptionData);

        // Fetch invoices
        const invoicesData = await apiRequest('/billing/invoices');
        setInvoices(invoicesData || []);

        // Fetch payment methods
        const paymentMethodsData = await apiRequest('/billing/payment-methods');
        setPaymentMethods(paymentMethodsData || []);
        
      } catch (err) {
        console.error('Billing fetch error:', err);
        showError('Billing Error', 'Failed to load billing information');
      } finally {
        setIsLoading(false);
      }
    };

    if (user) {
      fetchBillingData();
    }
  }, [user, apiRequest, showError]);

  // --- HANDLERS ---
  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      // Refetch all data
      const [subscriptionData, invoicesData, paymentMethodsData] = await Promise.all([
        apiRequest('/billing/subscription'),
        apiRequest('/billing/invoices'),
        apiRequest('/billing/payment-methods')
      ]);
      
      setSubscription(subscriptionData);
      setInvoices(invoicesData || []);
      setPaymentMethods(paymentMethodsData || []);
      
      showSuccess('Refreshed', 'Billing information updated');
    } catch (err) {
      showError('Refresh Error', 'Failed to update billing information');
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleDownloadInvoice = async (invoiceId) => {
    try {
      const blob = await apiRequest(`/billing/invoices/${invoiceId}/download`);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `invoice-${invoiceId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      showSuccess('Download Started', 'Invoice download started');
    } catch (err) {
      showError('Download Error', 'Failed to download invoice');
    }
  };

  // --- LOADING STATE ---
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 animate-spin text-indigo-600" />
          <span className="text-slate-600">Loading billing information...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 mb-1">Billing & Subscription</h1>
          <p className="text-slate-600">Manage your plan and payment history</p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="p-2.5 rounded-lg border border-slate-200 text-slate-600 hover:text-slate-900 hover:bg-white transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Current Subscription */}
      <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
        <div className="px-6 md:px-8 py-6 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <Crown className="text-indigo-600" size={20} />
            Current Subscription
          </h3>
          <p className="text-sm text-slate-500 mt-1">Your active plan and benefits</p>
        </div>
        
        <div className="p-6 md:p-8">
          {subscription ? (
            <div className="space-y-6">
              {/* Plan Info */}
              <div className="flex items-center justify-between p-6 border-2 border-indigo-100 rounded-2xl bg-gradient-to-br from-indigo-50/50 to-transparent">
                <div className="flex items-center gap-4">
                  <div className="w-14 h-14 bg-gradient-to-br from-indigo-500 to-violet-600 rounded-xl flex items-center justify-center shadow-lg">
                    <Crown className="text-white" size={24} />
                  </div>
                  <div>
                    <p className="text-lg font-bold text-slate-900 capitalize">{subscription.plan_name}</p>
                    <p className="text-sm text-slate-500">{subscription.description}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-2xl font-black text-slate-900">
                    ${subscription.price}/{subscription.billing_cycle}
                  </p>
                  <p className="text-xs text-slate-500">
                    Renews {new Date(subscription.renews_at).toLocaleDateString()}
                  </p>
                </div>
              </div>

              {/* Benefits */}
              <div>
                <h4 className="text-sm font-bold text-slate-700 uppercase tracking-wider mb-3">Plan Benefits</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {subscription.benefits?.map((benefit, index) => (
                    <div key={index} className="flex items-center gap-3 p-3 bg-slate-50 rounded-lg">
                      <Check className="text-emerald-600" size={16} />
                      <span className="text-sm text-slate-700">{benefit}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Usage Stats */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="text-center p-4 bg-gradient-to-br from-indigo-50 to-transparent rounded-xl border border-indigo-100/50">
                  <div className="text-xl font-bold text-slate-900">{subscription.courses_used || 0}</div>
                  <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mt-1">Courses Used</div>
                </div>
                <div className="text-center p-4 bg-gradient-to-br from-emerald-50 to-transparent rounded-xl border border-emerald-100/50">
                  <div className="text-xl font-bold text-slate-900">{subscription.courses_limit || '∞'}</div>
                  <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mt-1">Course Limit</div>
                </div>
                <div className="text-center p-4 bg-gradient-to-br from-violet-50 to-transparent rounded-xl border border-violet-100/50">
                  <div className="text-xl font-bold text-slate-900">{subscription.days_remaining || 0}</div>
                  <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mt-1">Days Remaining</div>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-8">
              <AlertCircle className="w-12 h-12 text-amber-500 mx-auto mb-3" />
              <h3 className="text-lg font-semibold text-slate-900 mb-2">No Active Subscription</h3>
              <p className="text-slate-600 mb-4">You don't have an active subscription plan.</p>
              <button className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded-lg font-medium transition-colors">
                View Plans
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Payment Methods */}
      <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
        <div className="px-6 md:px-8 py-6 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <CreditCard className="text-indigo-600" size={20} />
            Payment Methods
          </h3>
          <p className="text-sm text-slate-500 mt-1">Your registered payment information</p>
        </div>
        
        <div className="p-6 md:p-8">
          {paymentMethods.length > 0 ? (
            <div className="space-y-4">
              {paymentMethods.map((method) => (
                <div key={method.id} className="flex items-center justify-between p-5 border-2 border-slate-100 rounded-2xl hover:border-indigo-200 transition-colors">
                  <div className="flex items-center gap-4">
                    <div className="w-14 h-14 bg-gradient-to-br from-slate-500 to-slate-600 rounded-xl flex items-center justify-center shadow-lg">
                      <CreditCard className="text-white" size={24} />
                    </div>
                    <div>
                      <p className="text-sm font-bold text-slate-900 capitalize">{method.type}</p>
                      <p className="text-xs text-slate-500">
                        {method.type === 'card' 
                          ? `•••• ${method.last4}` 
                          : method.identifier
                        }
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 px-4 py-2 bg-emerald-50 border border-emerald-200 rounded-xl">
                    <Check size={16} className="text-emerald-600" />
                    <span className="text-xs font-bold text-emerald-700">
                      {method.is_default ? 'Default' : 'Verified'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <CreditCard className="w-12 h-12 text-slate-300 mx-auto mb-3" />
              <p className="text-slate-500">No payment methods on file</p>
            </div>
          )}
        </div>
      </div>

      {/* Invoice History */}
      <div className="bg-white border border-slate-200/60 rounded-3xl shadow-lg shadow-indigo-100/50 overflow-hidden">
        <div className="px-6 md:px-8 py-6 border-b border-slate-100 bg-gradient-to-r from-slate-50 to-transparent">
          <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <FileText className="text-indigo-600" size={20} />
            Invoice History
          </h3>
          <p className="text-sm text-slate-500 mt-1">Download your past invoices and receipts</p>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200">
                <th className="px-6 md:px-8 py-4 text-left">
                  <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Date</span>
                </th>
                <th className="px-6 py-4 text-left">
                  <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Description</span>
                </th>
                <th className="px-6 py-4 text-left">
                  <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Amount</span>
                </th>
                <th className="px-6 py-4 text-center">
                  <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Status</span>
                </th>
                <th className="px-6 md:px-8 py-4 text-right">
                  <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Invoice</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {invoices.length > 0 ? (
                invoices.map((invoice) => (
                  <tr key={invoice.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-6 md:px-8 py-5">
                      <p className="text-sm font-bold text-slate-900">
                        {new Date(invoice.date).toLocaleDateString()}
                      </p>
                      <p className="text-xs text-slate-500">
                        {new Date(invoice.date).toLocaleDateString('en-US', { year: 'numeric' })}
                      </p>
                    </td>
                    <td className="px-6 py-5">
                      <p className="text-sm font-medium text-slate-700">{invoice.description}</p>
                      <p className="text-xs text-slate-500">{invoice.plan_name}</p>
                    </td>
                    <td className="px-6 py-5">
                      <span className="text-sm font-black text-slate-900">
                        ${invoice.amount.toFixed(2)}
                      </span>
                    </td>
                    <td className="px-6 py-5 text-center">
                      <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold border ${
                        invoice.status === 'paid' 
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : invoice.status === 'pending'
                          ? 'bg-amber-50 text-amber-700 border-amber-200'
                          : 'bg-rose-50 text-rose-700 border-rose-200'
                      }`}>
                        {invoice.status === 'paid' && <Check size={12} />}
                        {invoice.status === 'pending' && <Calendar size={12} />}
                        {invoice.status === 'failed' && <AlertCircle size={12} />}
                        {invoice.status.charAt(0).toUpperCase() + invoice.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-6 md:px-8 py-5 text-right">
                      <button
                        onClick={() => handleDownloadInvoice(invoice.id)}
                        className="p-2 text-slate-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors"
                      >
                        <Download size={18} />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" className="px-6 py-12 text-center">
                    <FileText className="w-12 h-12 text-slate-300 mx-auto mb-3" />
                    <p className="text-slate-500">No invoices found</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {invoices.length > 0 && (
          <div className="p-4 md:p-6 bg-slate-50/50 border-t border-slate-200">
            <p className="text-center text-xs text-slate-500 font-medium">
              All invoices are generated automatically and available for download
            </p>
          </div>
        )}
      </div>

      {/* Info Banner */}
      <div className="bg-indigo-50 border border-indigo-200 rounded-2xl p-6">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 bg-indigo-100 rounded-xl flex items-center justify-center flex-shrink-0">
            <Shield className="text-indigo-600" size={20} />
          </div>
          <div>
            <h4 className="text-sm font-bold text-slate-900 mb-1">Secure Payment Processing</h4>
            <p className="text-xs text-slate-600 leading-relaxed">
              All transactions are processed securely with bank-level encryption. Your payment information is never stored on our servers and is PCI DSS compliant.
            </p>
          </div>
        </div>
      </div>

    </div>
  );
};

export default Billing;
