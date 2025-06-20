"use client";

import { useEffect, useRef, useState } from 'react';
import Image from 'next/image';

interface InteractiveBackgroundProps {
  children: React.ReactNode;
  className?: string;
}

export default function InteractiveBackground({ children, className = "" }: InteractiveBackgroundProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [isHovering, setIsHovering] = useState(false);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        setMousePosition({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top
        });
      }
    };

    const handleMouseEnter = () => setIsHovering(true);
    const handleMouseLeave = () => setIsHovering(false);

    const container = containerRef.current;
    if (container) {
      container.addEventListener('mousemove', handleMouseMove);
      container.addEventListener('mouseenter', handleMouseEnter);
      container.addEventListener('mouseleave', handleMouseLeave);
    }

    return () => {
      if (container) {
        container.removeEventListener('mousemove', handleMouseMove);
        container.removeEventListener('mouseenter', handleMouseEnter);
        container.removeEventListener('mouseleave', handleMouseLeave);
      }
    };
  }, []);

  return (
    <div 
      ref={containerRef}
      className={`relative min-h-screen overflow-hidden ${className}`}
    >
      {/* Background Image with Better Visibility */}
      <div className="fixed inset-0 z-0">
        <Image
          src="/abstract-black-white-background.jpg"
          alt="Abstract Background"
          fill
          className="object-cover brightness-45 contrast-150 opacity-70"
          quality={90}
          priority
        />
        {/* Dark overlay to maintain readability */}
        <div className="absolute inset-0 bg-black/60"></div>
      </div>

      {/* Visible Animated Wave Overlay */}
      <div className="fixed inset-0 z-10">
        <svg 
          className="w-full h-full opacity-30" 
          viewBox="0 0 1200 800" 
          preserveAspectRatio="xMidYMid slice"
        >
          <defs>
            <linearGradient id="waveGradient1" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#ffffff" stopOpacity="0.3" />
              <stop offset="50%" stopColor="#3b82f6" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#ffffff" stopOpacity="0.2" />
            </linearGradient>
            
            <linearGradient id="waveGradient2" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#60a5fa" stopOpacity="0.2" />
              <stop offset="50%" stopColor="#ffffff" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.2" />
            </linearGradient>
            
            <linearGradient id="waveGradient3" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.1" />
              <stop offset="50%" stopColor="#60a5fa" stopOpacity="0.2" />
              <stop offset="100%" stopColor="#ffffff" stopOpacity="0.1" />
            </linearGradient>
          </defs>
          
          <path 
            d="M0,400 Q300,200 600,400 T1200,400 V800 H0 Z" 
            fill="url(#waveGradient1)"
            className="animate-wave-slow"
          />
          <path 
            d="M0,500 Q400,300 800,500 T1600,500 V800 H0 Z" 
            fill="url(#waveGradient2)"
            className="animate-wave-medium"
          />
          <path 
            d="M0,600 Q200,400 400,600 T800,600 V800 H0 Z" 
            fill="url(#waveGradient3)"
            className="animate-wave-fast"
          />
        </svg>
      </div>

      {/* Cursor Glow Effect - Your Implementation */}
      {isHovering && (
        <div
          className="absolute pointer-events-none z-20 transition-opacity duration-300"
          style={{
            left: mousePosition.x - 100,
            top: mousePosition.y - 100,
            width: 200,
            height: 200,
            opacity: isHovering ? 1 : 0,
          }}
        >
          <div 
            className="w-full h-full rounded-full opacity-50 animate-pulse"
            style={{
              background: 'radial-gradient(circle at center, rgba(59, 130, 246, 0.5) 0%, rgba(255, 255, 255, 0.2) 30%, transparent 70%)',
              filter: 'blur(30px)'
            }}
          />
        </div>
      )}

      {/* Content Layer */}
      <div className="relative z-30">
        {children}
      </div>

      {/* Custom CSS for animations */}
      <style jsx global>{`
        @keyframes wave-slow {
          0%, 100% { 
            transform: translateX(0) scaleY(1); 
          }
          50% { 
            transform: translateX(-25px) scaleY(1.1); 
          }
        }
        
        @keyframes wave-medium {
          0%, 100% { 
            transform: translateX(0) scaleY(1); 
          }
          50% { 
            transform: translateX(25px) scaleY(0.9); 
          }
        }
        
        @keyframes wave-fast {
          0%, 100% { 
            transform: translateX(0) scaleY(1); 
          }
          50% { 
            transform: translateX(-15px) scaleY(1.2); 
          }
        }
        
        .animate-wave-slow {
          animation: wave-slow 8s ease-in-out infinite;
        }
        
        .animate-wave-medium {
          animation: wave-medium 6s ease-in-out infinite reverse;
        }
        
        .animate-wave-fast {
          animation: wave-fast 4s ease-in-out infinite;
        }
      `}</style>
    </div>
  );
}