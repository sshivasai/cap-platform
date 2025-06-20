import Image from "next/image";
import Link from "next/link";

export default function Header() {
  return (
    <header className="fixed top-0 left-0 right-0 z-50">
      <nav className="flex items-center justify-between px-6 py-4 lg:px-8 bg-black/20 backdrop-blur-sm border-b border-white/10">
        <div className="flex items-center space-x-2">
          <Image 
            src="/Logo_BW.png" 
            alt="CAP Logo" 
            width={120} 
            height={30}
            className="w-auto h-auto max-w-full max-h-12"
          />
        </div>
        <div className="hidden md:flex items-center space-x-8">
          <Link href="#features" className="text-gray-300 hover:text-white transition-colors">
            Features
          </Link>
          <Link href="#integrations" className="text-gray-300 hover:text-white transition-colors">
            Integrations
          </Link>
          <Link href="#pricing" className="text-gray-300 hover:text-white transition-colors">
            Pricing
          </Link>
          <Link href="/login" className="text-gray-300 hover:text-white transition-colors">
            Sign In
          </Link>
          <Link 
            href="/register" 
            className="bg-gradient-to-r from-gray-700/80 to-gray-800/80 hover:from-gray-600/80 hover:to-gray-700/80 px-4 py-2 rounded-md transition-all duration-200 border border-gray-600/50 backdrop-blur-sm"
          >
            Get Started
          </Link>
        </div>
      </nav>
    </header>
  );
}