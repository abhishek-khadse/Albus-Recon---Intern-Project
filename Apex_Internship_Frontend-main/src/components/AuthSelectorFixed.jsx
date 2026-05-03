import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { User, ArrowRight, Eye, EyeOff, Shield, Lock, Terminal, Cpu, Wallet } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { EthereumProvider } from '@walletconnect/ethereum-provider';
import Web3 from 'web3';

const AuthSelector = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [formData, setFormData] = useState({ username: '', password: '' });
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [showWalletOptions, setShowWalletOptions] = useState(false);
  const [hasExtension, setHasExtension] = useState(false);

  React.useEffect(() => {
    if (window.ethereum) {
      setHasExtension(true);
    }
  }, []);
  
  const navigate = useNavigate();
  const { login, loginWithWeb3, apiRequest } = useAuth();

  const handleWeb3Auth = async (web3) => {
    const accounts = await web3.eth.getAccounts();
    if (!accounts || accounts.length === 0) {
      throw new Error('No accounts found');
    }
    const walletAddress = accounts[0];
    
    // 1. Get challenge nonce
    const response = await apiRequest(`/auth/challenge?walletAddress=${walletAddress}`);
    const nonce = response.nonce;
    const message = `Sign this message to authenticate with Apex: ${nonce}`;
    
    // 2. Sign message
    const signature = await web3.eth.personal.sign(message, walletAddress, '');
    
    // 3. Login
    const success = await loginWithWeb3(walletAddress, signature);
    if (success) {
      navigate('/dashboard');
    }
  };

  const connectInjected = async () => {
    try {
      setIsLoading(true);
      setErrorMsg('');
      if (!window.ethereum) throw new Error("Browser wallet not detected.");
      
      const web3 = new Web3(window.ethereum);
      await window.ethereum.request({ method: 'eth_requestAccounts' });
      await handleWeb3Auth(web3);
    } catch (error) {
      console.error('Wallet connection error:', error);
      // Catch user rejection nicely
      if (error.code === 4001 || error.message?.includes('User denied')) {
        setErrorMsg('Wallet connection cancelled.');
      } else {
        setErrorMsg(error.message || 'Wallet connection failed');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const connectWalletConnect = async () => {
    try {
      setIsLoading(true);
      setErrorMsg('');
      
      const provider = await EthereumProvider.init({
        projectId: 'cba56860ee5979faf47bc7e017ee9662', // User's WalletConnect Cloud Project ID
        chains: [1], 
        optionalChains: [1, 5, 137, 56, 11155111], // Mainnet, Goerli, Polygon, BSC, Sepolia
        showQrModal: true,
        metadata: {
          name: 'ACS Internship',
          description: 'Cyber Security Training',
          url: window.location.origin,
          icons: ['https://avatars.githubusercontent.com/u/37784886']
        }
      });
      
      await provider.connect();
      const web3 = new Web3(provider);
      await handleWeb3Auth(web3);
    } catch (error) {
      console.error('WalletConnect error:', error);
      if (error.message?.includes('User closed modal') || error.message?.includes('User denied')) {
        setErrorMsg('Wallet connection cancelled.');
      } else {
        setErrorMsg(error.message || 'Wallet connection failed');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    setErrorMsg('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMsg('');

    try {
      console.log('[AuthSelector] Starting login with:', formData.username);
      const success = await login(formData.username, formData.password);
      console.log('[AuthSelector] Login success:', success);
      
      if (success) {
        console.log('[AuthSelector] Navigating to dashboard...');
        navigate('/dashboard');
      } else {
        console.log('[AuthSelector] Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      setErrorMsg(error.message || 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black flex items-center justify-center p-4 relative overflow-hidden">
      {/* Animated Background Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-0 w-96 h-96 bg-gradient-to-br from-cyan-500/10 to-transparent rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-0 w-64 h-64 bg-gradient-to-tl from-purple-500/10 to-transparent rounded-full blur-2xl animate-pulse"></div>
        {/* Floating Code Elements */}
        <div className="absolute top-20 left-10 text-cyan-500/20 font-mono text-xs animate-pulse">0x742d...</div>
        <div className="absolute top-32 right-20 text-purple-500/20 font-mono text-xs animate-pulse">0x9f1a2...</div>
        <div className="absolute bottom-40 left-32 text-green-500/20 font-mono text-xs animate-pulse">0x3c4d5...</div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        className="w-full max-w-6xl flex rounded-2xl shadow-2xl overflow-hidden relative z-10 border border-gray-800"
      >
        {/* Left Section - ACS Internship Info */}
        <div className="w-1/2 bg-gradient-to-br from-gray-900 via-indigo-900/50 to-black p-12 flex flex-col justify-between relative">
          {/* Circuit Board Pattern Overlay */}
          <div className="absolute inset-0 opacity-10">
            <div className="grid grid-cols-8 grid-rows-8 h-full">
              {[...Array(64)].map((_, i) => (
                <div key={i} className={`border ${i % 4 === 0 || i % 4 === 1 ? 'border-cyan-500/30' : 'border-purple-500/20'}`}></div>
              ))}
            </div>
          </div>
          
          <div className="relative z-10">
            <div className="flex items-center mb-8">
              <div className="flex items-center gap-3">
                <span className="text-white text-2xl font-bold">ACS</span>
                <span className="text-white text-2xl">INTERNSHIP</span>
              </div>
            </div>
            <h1 className="text-5xl font-bold text-white mb-4">
              Cyber Security <span className="text-cyan-400">Training</span>
            </h1>
            <p className="text-gray-400 text-lg mb-8">
              Master cybersecurity fundamentals through hands-on learning. Build skills, solve challenges, and launch your career in information security.
            </p>
            <div className="space-y-6">
              <div className="flex items-start group">
                <div className="w-12 h-12 bg-gradient-to-br from-cyan-500/20 to-cyan-600/40 rounded-lg flex items-center justify-center mr-4 group-hover:scale-110 transition-transform">
                  <Terminal className="w-6 h-6 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-white font-semibold text-lg group-hover:text-cyan-400 transition-colors">Learn Security</h3>
                  <p className="text-gray-400 text-sm">Comprehensive curriculum covering network security, cryptography, and secure coding practices</p>
                </div>
              </div>
              <div className="flex items-start group">
                <div className="w-12 h-12 bg-gradient-to-br from-purple-500/20 to-purple-600/40 rounded-lg flex items-center justify-center mr-4 group-hover:scale-110 transition-transform">
                  <Lock className="w-6 h-6 text-purple-400" />
                </div>
                <div>
                  <h3 className="text-white font-semibold text-lg group-hover:text-purple-400 transition-colors">Solve Challenges</h3>
                  <p className="text-gray-400 text-sm">Real-world scenarios and CTF challenges to test your skills</p>
                </div>
              </div>
              <div className="flex items-start group">
                <div className="w-12 h-12 bg-gradient-to-br from-green-500/20 to-green-600/40 rounded-lg flex items-center justify-center mr-4 group-hover:scale-110 transition-transform">
                  <Cpu className="w-6 h-6 text-green-400" />
                </div>
                <div>
                  <h3 className="text-white font-semibold text-lg group-hover:text-green-400 transition-colors">Launch Career</h3>
                  <p className="text-gray-400 text-sm">Build portfolio and connect with top security employers</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Section - Login Form */}
        <div className="w-1/2 bg-gray-950 p-12 flex flex-col justify-center relative">
          {/* Subtle Grid Pattern */}
          <div className="absolute inset-0 opacity-5">
            <div className="grid grid-cols-12 gap-px h-full">
              {[...Array(12)].map((_, i) => (
                <div key={i} className="border border-gray-800/30"></div>
              ))}
            </div>
          </div>
          
          <div className="relative z-10 w-full max-w-sm">
            <div className="flex items-center justify-center mb-6">
              <img src="/image/AlbusSecurityLogo.png" alt="Albus Security" className="w-35 h-auto object-contain" />
            </div>
            {!showWalletOptions ? (
              <motion.button
                onClick={() => {
                  if (hasExtension) {
                    connectInjected();
                  } else {
                    connectWalletConnect();
                  }
                }}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                disabled={isLoading}
                type="button"
                className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-semibold py-3 px-4 rounded-lg transition-all duration-300 flex items-center justify-center gap-2 shadow-lg shadow-blue-500/25 mb-3 disabled:opacity-50"
              >
                <Wallet size={20} />
                {hasExtension ? 'Connect MetaMask' : 'Connect Wallet'}
              </motion.button>
            ) : null}

            {hasExtension && !showWalletOptions && (
              <button
                onClick={() => connectWalletConnect()}
                className="w-full text-xs text-gray-400 hover:text-white mb-6 transition-colors text-center"
              >
                Don't have MetaMask? Use QR Code
              </button>
            )}

            {showWalletOptions && (
              <div className="space-y-3 mb-6 bg-gray-900/50 p-4 rounded-xl border border-gray-800">
                <p className="text-sm text-gray-400 text-center mb-3">Select your connection method</p>
                <motion.button
                  onClick={connectInjected}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  disabled={isLoading}
                  type="button"
                  className="w-full bg-gray-800 hover:bg-gray-700 text-white font-medium py-2.5 px-4 rounded-lg transition-colors border border-gray-700 flex items-center justify-center gap-2"
                >
                  <img src="https://upload.wikimedia.org/wikipedia/commons/3/36/MetaMask_Fox.svg" alt="MetaMask" className="w-5 h-5" />
                  Browser Wallet (MetaMask)
                </motion.button>
                <motion.button
                  onClick={connectWalletConnect}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  disabled={isLoading}
                  type="button"
                  className="w-full bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 font-medium py-2.5 px-4 rounded-lg transition-colors border border-blue-500/30 flex items-center justify-center gap-2"
                >
                  Mobile Wallet (WalletConnect)
                </motion.button>
                <button 
                  onClick={() => setShowWalletOptions(false)}
                  disabled={isLoading}
                  type="button"
                  className="w-full text-xs text-gray-500 hover:text-gray-300 mt-2 transition-colors py-1"
                >
                  Cancel
                </button>
              </div>
            )}
            
            <div className="flex items-center my-6">
              <div className="flex-grow border-t border-gray-700"></div>
              <span className="mx-4 text-gray-500 text-sm">OR</span>
              <div className="flex-grow border-t border-gray-700"></div>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Error Message */}
              {errorMsg && (
                <div className="bg-red-500/20 border border-red-500/50 text-red-400 px-4 py-3 rounded-lg text-sm mb-4">
                  {errorMsg}
                </div>
              )}

              {/* Username Field */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Username
                </label>
                <div className="relative">
                  <input
                    type="text"
                    name="username"
                    value={formData.username}
                    onChange={handleInputChange}
                    className="w-full px-4 py-3 bg-gray-900/80 backdrop-blur border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition-all duration-300"
                    placeholder="Enter your username"
                    disabled={isLoading}
                  />
                  <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                    <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse"></div>
                  </div>
                </div>
              </div>

              {/* Password Field */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    name="password"
                    value={formData.password}
                    onChange={handleInputChange}
                    className="w-full px-4 py-3 pr-12 bg-gray-900/80 backdrop-blur border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent transition-all duration-300"
                    placeholder="Enter your password"
                    disabled={isLoading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-cyan-400 transition-colors"
                  >
                    {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                  </button>
                </div>
              </div>

              {/* Remember Me Checkbox */}
              <div className="flex items-center justify-between">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="w-4 h-4 bg-gray-900/80 backdrop-blur border-gray-600 rounded focus:ring-2 focus:ring-cyan-500 focus:ring-offset-0"
                  />
                  <span className="ml-2 text-sm text-gray-300">Remember me</span>
                </label>
                <Link to="/forgot-password" className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors">
                  Forgot password?
                </Link>
              </div>

              {/* Sign In Button */}
              <motion.button
                type="submit"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                disabled={isLoading}
                className="w-full bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-700 hover:to-purple-700 text-white font-semibold py-3 px-4 rounded-lg transition-all duration-300 flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/25 disabled:opacity-50"
              >
                {isLoading ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white/30 rounded-full animate-spin"></div>
                    Signing in...
                  </>
                ) : (
                  <>
                    Sign in
                    <ArrowRight size={20} />
                  </>
                )}
              </motion.button>
            </form>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default AuthSelector;
