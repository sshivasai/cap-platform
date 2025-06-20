"use client";

import InteractiveBackground from "@/components/InteractiveBackground";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import Image from "next/image";
import Link from "next/link";

export default function Home() {
  return (
    <InteractiveBackground>
      {/* Custom CSS */}
      <style jsx global>{`
        @keyframes scroll {
          0% { transform: translateX(0); }
          100% { transform: translateX(-100%); }
        }
        
        @keyframes fadeInUp {
          from {
            opacity: 0;
            transform: translateY(30px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        
        @keyframes floatSlow {
          0%, 100% { transform: translateY(0px); }
          50% { transform: translateY(-20px); }
        }
        
        @keyframes floatDelayed {
          0%, 100% { transform: translateY(0px); }
          50% { transform: translateY(-15px); }
        }
        
        .scroll-animation {
          animation: scroll 30s linear infinite;
        }
        
        .animate-fade-up {
          animation: fadeInUp 0.6s ease-out forwards;
        }
        
        .animate-float {
          animation: floatSlow 6s ease-in-out infinite;
        }
        
        .animate-float-delayed {
          animation: floatDelayed 8s ease-in-out infinite;
        }
        
        .animate-delay-200 {
          animation-delay: 0.2s;
        }
        
        .animate-delay-400 {
          animation-delay: 0.4s;
        }

        /* Ensure content isn't hidden under fixed header */
        main {
          padding-top: 80px; /* Adjust based on header height */
        }
      `}</style>

      <Header />

      <main>
        {/* Hero Section */}
        <section className="relative px-6 pt-20 pb-32 lg:px-8">
          <div className="mx-auto max-w-4xl text-center">
            {/* Logo */}
            <div className="mb-8 animate-pulse">
              <Image
                src="/Logo_BW.png"
                alt="CAP Logo"
                width={300}
                height="300"
                className="mx-auto mb-4 drop-shadow-2xl"
              />
              <div className="text-6xl md:text-8xl font-bold bg-gradient-to-r from-gray-100 via-gray-300 to-gray-500 bg-clip-text text-transparent">
                CAP
              </div>
            </div>
            
            <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-6 animate-fade-up">
              <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
                Conversational AI
              </span>
              <br />
              <span className="bg-gradient-to-r from-gray-300 to-gray-500 bg-clip-text text-transparent">
                Platform
              </span>
            </h1>
            
            <p className="text-xl md:text-2xl text-gray-200 mb-12 max-w-3xl mx-auto leading-relaxed animate-fade-up animate-delay-200">
              Build sophisticated AI agents with voice, text, and phone capabilities. 
              Enterprise-grade platform with advanced integrations and scalable architecture.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center animate-fade-up animate-delay-400">
              <Link 
                href="/register"
                className="group bg-gradient-to-r from-white/90 to-gray-200/90 text-black px-8 py-4 rounded-lg font-semibold text-lg hover:from-gray-100/90 hover:to-gray-300/90 transition-all duration-300 shadow-lg hover:shadow-2xl transform hover:scale-105 backdrop-blur-sm"
              >
                Start Building 
                <span className="inline-block ml-2 transition-transform group-hover:translate-x-1">→</span>
              </Link>
              <Link 
                href="/demo"
                className="group border border-gray-600/80 hover:border-gray-400/80 px-8 py-4 rounded-lg font-semibold text-lg transition-all duration-300 hover:bg-gray-900/50 hover:shadow-lg transform hover:scale-105 backdrop-blur-sm"
              >
                <span className="mr-2">🎬</span>
                View Demo
              </Link>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section id="features" className="px-6 py-24 lg:px-8">
          <div className="mx-auto max-w-7xl">
            <div className="text-center mb-16">
              <h2 className="text-3xl md:text-5xl font-bold mb-4">
                <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
                  Enterprise-Grade Features
                </span>
              </h2>
              <p className="text-xl text-gray-300 max-w-2xl mx-auto">
                Everything you need to build, deploy, and scale conversational AI agents
              </p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
              {/* Multi-Modal Support */}
              <div className="group p-6 rounded-lg border border-gray-800/50 hover:border-blue-500/50 transition-all duration-300 hover:bg-gray-900/30 transform hover:scale-105 hover:shadow-xl backdrop-blur-sm">
                <div className="w-12 h-12 mb-4 bg-gradient-to-r from-blue-600 to-blue-800 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-white">
                    <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>
                <h3 className="text-xl font-semibold mb-2 text-gray-100 group-hover:text-white transition-colors">Multi-Modal AI</h3>
                <p className="text-gray-400 leading-relaxed group-hover:text-gray-200 transition-colors">
                  Support for text, voice, and phone interactions with seamless switching between modes
                </p>
              </div>

              {/* Visual Workflow Builder */}
              <div className="group p-6 rounded-lg border border-gray-800/50 hover:border-blue-500/50 transition-all duration-300 hover:bg-gray-900/30 transform hover:scale-105 hover:shadow-xl backdrop-blur-sm">
                <div className="w-12 h-12 mb-4 bg-gradient-to-r from-gray-600 to-gray-800 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-white">
                    <rect x="3" y="3" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="2"/>
                    <rect x="15" y="3" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="2"/>
                    <rect x="9" y="15" width="6" height="6" rx="1" stroke="currentColor" strokeWidth="2"/>
                    <path d="M9 6H15" stroke="currentColor" strokeWidth="2"/>
                    <path d="M12 9V15" stroke="currentColor" strokeWidth="2"/>
                  </svg>
                </div>
                <h3 className="text-xl font-semibold mb-2 text-gray-100 group-hover:text-white transition-colors">Visual Builder</h3>
                <p className="text-gray-400 leading-relaxed group-hover:text-gray-200 transition-colors">
                  Drag-and-drop workflow creation with no-code agent configuration
                </p>
              </div>

              {/* MCP Integration */}
              <div className="group p-6 rounded-lg border border-gray-800/50 hover:border-blue-500/50 transition-all duration-300 hover:bg-gray-900/30 transform hover:scale-105 hover:shadow-xl backdrop-blur-sm">
                <div className="w-12 h-12 mb-4 bg-gradient-to-r from-blue-700 to-blue-900 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-white">
                    <path d="M10 13A5 5 0 0 0 7.54 7.54L4.93 4.93A10 10 0 1 1 19.07 19.07L16.46 16.46A5 5 0 0 0 10 13Z" stroke="currentColor" strokeWidth="2"/>
                    <path d="M10 13L12 15L22 5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>
                <h3 className="text-xl font-semibold mb-2 text-gray-100 group-hover:text-white transition-colors">MCP Protocol</h3>
                <p className="text-gray-400 leading-relaxed group-hover:text-gray-200 transition-colors">
                  Native Model Context Protocol support for future-proof integrations
                </p>
              </div>

              {/* Enterprise Security */}
              <div className="group p-6 rounded-lg border border-gray-800/50 hover:border-blue-500/50 transition-all duration-300 hover:bg-gray-900/30 transform hover:scale-105 hover:shadow-xl backdrop-blur-sm">
                <div className="w-12 h-12 mb-4 bg-gradient-to-r from-gray-700 to-black rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-white">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke="currentColor" strokeWidth="2"/>
                    <circle cx="12" cy="16" r="1" fill="currentColor"/>
                    <path d="M7 11V7A5 5 0 0 1 17 7V11" stroke="currentColor" strokeWidth="2"/>
                  </svg>
                </div>
                <h3 className="text-xl font-semibold mb-2 text-gray-100 group-hover:text-white transition-colors">Enterprise Security</h3>
                <p className="text-gray-400 leading-relaxed group-hover:text-gray-200 transition-colors">
                  Multi-tenant architecture with RBAC and comprehensive security controls
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Integrations Section */}
        <section id="integrations" className="px-6 py-24 lg:px-8 bg-black/20 backdrop-blur-sm relative overflow-hidden">
          <div className="mx-auto max-w-6xl text-center">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
                Powered by Industry Leaders
              </span>
            </h2>
            <p className="text-gray-300 mb-12 text-lg">
              Seamlessly integrate with the tools and platforms you already use
            </p>
            
            {/* Scrolling Integration Logos */}
            <div className="relative overflow-hidden py-8">
              <div className="flex items-center space-x-16 scroll-animation whitespace-nowrap">
                {/* First set of logos */}
                <div className="flex items-center justify-center">
                  <svg width="120" height="40" viewBox="0 0 120 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="10" y="25" className="text-lg font-bold">OpenAI</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="120" height="40" viewBox="0 0 120 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="5" y="25" className="text-lg font-bold">Anthropic</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="100" height="40" viewBox="0 0 100 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="15" y="25" className="text-lg font-bold">Twilio</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="130" height="40" viewBox="0 0 130 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="5" y="25" className="text-lg font-bold">ElevenLabs</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="120" height="40" viewBox="0 0 120 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="5" y="25" className="text-lg font-bold">Deepgram</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="80" height="40" viewBox="0 0 80 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="15" y="25" className="text-lg font-bold">Stripe</text>
                  </svg>
                </div>

                {/* Duplicate set for seamless loop */}
                <div className="flex items-center justify-center">
                  <svg width="120" height="40" viewBox="0 0 120 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="10" y="25" className="text-lg font-bold">OpenAI</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="120" height="40" viewBox="0 0 120 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="5" y="25" className="text-lg font-bold">Anthropic</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="100" height="40" viewBox="0 0 100 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="15" y="25" className="text-lg font-bold">Twilio</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="130" height="40" viewBox="0 0 130 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="5" y="25" className="text-lg font-bold">ElevenLabs</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="120" height="40" viewBox="0 0 120 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="5" y="25" className="text-lg font-bold">Deepgram</text>
                  </svg>
                </div>
                
                <div className="flex items-center justify-center">
                  <svg width="80" height="40" viewBox="0 0 80 40" className="fill-gray-400 hover:fill-white transition-colors duration-300">
                    <text x="15" y="25" className="text-lg font-bold">Stripe</text>
                  </svg>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Pricing Preview */}
        <section id="pricing" className="px-6 py-24 lg:px-8">
          <div className="mx-auto max-w-6xl text-center">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              <span className="bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
                Simple, Transparent Pricing
              </span>
            </h2>
            <p className="text-gray-300 mb-12 text-lg">
              Start free, scale as you grow
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {/* Free Tier */}
              <div className="p-8 rounded-lg border border-gray-800/50 hover:border-gray-600/50 transition-all duration-300 backdrop-blur-sm hover:bg-gray-900/30">
                <h3 className="text-2xl font-bold mb-2">Free</h3>
                <p className="text-gray-400 mb-6">Perfect for getting started</p>
                <div className="text-4xl font-bold mb-6">$0<span className="text-lg text-gray-400">/month</span></div>
                <ul className="text-left text-gray-300 space-y-3 mb-8">
                  <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> 1 AI Agent</li>
                  <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> 100 conversations/month</li>
                  <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> Basic integrations</li>
                  <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> Community support</li>
                  <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> API support</li>
                </ul>
                <Link href="/register" className="block w-full bg-gradient-to-r from-gray-700/80 to-gray-800/80 hover:from-gray-600/80 hover:to-gray-700/80 px-6 py-3 rounded-lg font-semibold transition-all duration-200 backdrop-blur-sm">
                  Get Started
                </Link>
              </div>

              {/* Pro Tier */}
              <div className="p-8 rounded-lg border border-gray-600/50 bg-gradient-to-b from-gray-900/50 to-gray-950/50 relative transform hover:scale-105 transition-all duration-300 hover:shadow-2xl backdrop-blur-sm">
                <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-gradient-to-r from-white/90 to-gray-300/90 text-black px-4 py-1 rounded-full text-sm font-semibold animate-pulse">
                  Most Popular
                </div>
                <h3 className="text-2xl font-bold mb-2">Pro</h3>
                <p className="text-gray-400 mb-6">For growing businesses</p>
                <div className="text-4xl font-bold mb-6">$99<span className="text-lg font-medium">/month</span></div>
                <ul className="text-left text-gray-300 space-y-3 mb-8">
                    <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> 10 AI Agents</li>
                    <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> 10,000 conversations/month</li>
                    <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> All integrations</li>
                    <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> Priority support</li>
                    <li className="flex items-center"><span className="text-green-600 mr-2">✓</span> Advanced analytics</li>
                </ul>
                <Link href="/register" className="block w-full bg-gradient-to-r from-white/90 to-gray-200/90 text-black hover:from-gray-100/90 hover:to-gray-300/90 px-6 py-3 rounded-lg font-semibold transition-all duration-200 transform hover:scale-105 backdrop-blur-sm">
                    Start Pro Trial
                </Link>
              </div>

              {/* Enterprise Tier */}
              <div className="p-8 rounded-lg border border-gray-800/50 hover:border-gray-600/50 transition-all duration-300 backdrop-blur-sm hover:bg-gray-900/30">
                <h3 className="text-2xl font-bold mb-2">Enterprise</h3>
                <p className="text-gray-400 mb-6">For large organizations</p>
                <div className="text-2xl font-bold mb-6">Custom</div>
                <ul className="text-left text-gray-600 space-y-3 mb-8">
                    <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> Unlimited agents</li>
                    <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> Unlimited conversations</li>
                    <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> Custom integrations</li>
                    <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> Dedicated support</li>
                    <li className="flex items-center"><span className="text-green-400 mr-2">✓</span> White-label options</li>
                </ul>
                <Link href="/contact" className="block w-full bg-gradient-to-r from-gray-700/80 to-gray-800/80 hover:from-gray-600/80 hover:to-gray-700/80 px-6 py-3 rounded-lg font-semibold transition-all duration-200 backdrop-blur-sm">
                  Contact Sales
                </Link>
              </div>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="px-6 py-24 lg:px-8 bg-gradient-to-r from-gray-900/50 to-black/50 backdrop-blur-sm">
          <div className="mx-auto max-w-4xl text-center">
            <h2 className="text-3xl md:text-5xl font-bold mb-6">
              <span className="bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent">
                Ready to Build the Future?
              </span>
            </h2>
            <p className="text-xl text-gray-200 mb-8 max-w-2xl mx-auto">
              Join thousands of developers and businesses building amazing conversational experiences with CAP
            </p>
            <Link 
              href="/register"
              className="inline-block bg-gradient-to-r from-white/90 to-gray-200/90 text-black px-10 py-4 rounded-lg font-semibold text-xl transition-all duration-200 shadow-lg transform hover:scale-105 backdrop-blur-sm"
            >
              Start Building Today →
            </Link>
          </div>
        </section>
      </main>

      <Footer />
    </InteractiveBackground>
  );
}