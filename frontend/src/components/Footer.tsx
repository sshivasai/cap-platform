import Link from "next/link";

export default function Footer() {
  return (
    <footer className="border-t border-gray-800/50 px-6 py-12 lg:px-8 bg-black/30 backdrop-blur-sm">
      <div className="mx-auto max-w-6xl">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div>
            <div className="text-2xl font-bold bg-gradient-to-r from-gray-200 to-gray-400 bg-clip-text text-transparent mb-4">
              CAP
            </div>
            <p className="text-gray-400">
              The future of conversational AI platforms
            </p>
          </div>
          
          <div>
            <h4 className="font-semibold mb-4 text-gray-200">Product</h4>
            <ul className="space-y-2 text-gray-400">
              <li><Link href="/features" className="hover:text-white transition-colors">Features</Link></li>
              <li><Link href="/pricing" className="hover:text-white transition-colors">Pricing</Link></li>
              <li><Link href="/docs" className="hover:text-white transition-colors">Documentation</Link></li>
              <li><Link href="/api" className="hover:text-white transition-colors">API</Link></li>
            </ul>
          </div>
          
          <div>
            <h4 className="font-semibold mb-4 text-gray-200">Company</h4>
            <ul className="space-y-2 text-gray-400">
              <li><Link href="/about" className="hover:text-white transition-colors">About</Link></li>
              <li><Link href="/blog" className="hover:text-white transition-colors">Blog</Link></li>
              <li><Link href="/careers" className="hover:text-white transition-colors">Careers</Link></li>
              <li><Link href="/contact" className="hover:text-white transition-colors">Contact</Link></li>
            </ul>
          </div>
          
          <div>
            <h4 className="font-semibold mb-4 text-gray-200">Legal</h4>
            <ul className="space-y-2 text-gray-400">
              <li><Link href="/privacy" className="hover:text-white transition-colors">Privacy</Link></li>
              <li><Link href="/terms" className="hover:text-white transition-colors">Terms</Link></li>
              <li><Link href="/security" className="hover:text-white transition-colors">Security</Link></li>
            </ul>
          </div>
        </div>
        
        <div className="border-t border-gray-800/50 mt-8 pt-8 text-center text-gray-400">
          <p>© 2025 CAP Platform. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
}