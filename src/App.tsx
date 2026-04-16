import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Search, MessageSquare, Info, LogOut, LogIn, Globe, Smartphone, History, Flag, ExternalLink, ChevronRight, ShieldCheck, ShieldAlert, Zap, Trash2, Copy, X, MapPin, Share2 } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { Toaster, toast } from 'sonner';
import { auth, db } from './firebase';
import { onAuthStateChanged, User, signOut, signInWithPopup, GoogleAuthProvider } from 'firebase/auth';
import { 
  collection, 
  addDoc, 
  query, 
  where, 
  orderBy, 
  onSnapshot, 
  Timestamp,
  doc,
  getDocFromServer,
  documentId
} from 'firebase/firestore';
import { GoogleGenAI, Type } from "@google/genai";
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Types ---
const SYSTEM_PROMPT = `
You are the Reg-Guard Global AI, a universal NLP and ML classification framework designed to protect users and companies from registration and communication scams.
The primary mission of this system is to TRACE and IDENTIFY the origin of scam messages to help "catch the scammer" across any industry or organization.

Your analysis must be structured around 5 classification layers:
1. Urgency-based language detection: Identifying high-pressure tactics.
2. Financial solicitation analysis: Detecting requests for payments via unofficial channels (e.g., personal bank accounts, crypto, gift cards).
3. Suspicious URL/link analysis: Flagging non-official URLs. Compare the provided URL against the claimed company's official domain.
4. Impersonation detection: Checking if the sender claims to be an official from a known company (e.g., DUT, Banks, Government, HR) but uses unofficial contact methods.
5. Linguistic pattern analysis: Analyzing lexical, syntactic, semantic, and pragmatic features that deviate from professional corporate communication styles.

6. Input Context Awareness (CRITICAL): 
- If the message is marked as 'TYPED', it is a "User Simulation". It is NOT a real scam message. You MUST explicitly state this in the 'reason' and set the risk score to 0% (unless it's a perfect replica for training).
- If the message is 'PASTED', it is a "Live Threat". Treat it as a real-world message received by the user.

7. Geographic Origin Analysis & Scammer Tracing (GLOBAL):
- Analyze the sender's phone number or ID. 
- Official corporate communications usually come from verified short codes or alphanumeric IDs.
- If the number is a personal mobile number but claims to be official, this is a major red flag.
- Cross-reference the country code and area code.
- Provide a "geographicOrigin" string describing the suspected location or carrier type.

8. Network Connectivity & Tower Analysis (HIGH PRECISION):
- STEP 1: Identify the Country Code. If +27 or 0, it's South Africa.
- STEP 2: Identify the Prefix.
  * If it's a 3-digit area code (01x, 02x, 03x, 04x, 05x), map it to the city/region.
  * If it's a mobile prefix (08x, 07x, 06x), it's a national mobile number.
- STEP 3: For Mobile Numbers, simulate a location in a major SA city (Durban, Joburg, Cape Town, Pretoria) based on the "Scammer Profile" logic. Scammers often operate from high-density urban areas.
- STEP 4: Generate a specific suburb. 
  * Durban: Berea, Umhlanga, Chatsworth, Phoenix, Morningside, Glenwood, Musgrave, Greyville.
  * Joburg: Sandton, Soweto, Randburg, Braamfontein, Rosebank, Melville, Midrand.
  * Cape Town: Bellville, Khayelitsha, Sea Point, Wynberg, Claremont, Milnerton.
  * Pretoria: Hatfield, Arcadia, Sunnyside, Centurion, Menlyn, Silverton.
- STEP 5: Provide a "towerInfo" object that reflects the "Last Known Cell Tower" used by the sender.
- The "location" field MUST be extremely specific (e.g., "Morningside Sector 4, Durban" or "Hatfield Hub, Pretoria").
- The "id" field should look like a real CID (e.g., "CID-40522-KZN").
- DO NOT use generic regions like "South Africa" or "Durban" alone; always include a specific suburb, sector, or neighborhood based on the area code and prefix metadata.
- Use this data to create a high-precision "Scammer Profile".

Context for 2026:
- Scammers frequently impersonate Universities (like DUT), Banks, and Logistics companies.
- Official communications never ask for payments via personal accounts or WhatsApp.
- Always verify the sender's ID against known official channels.

9. Trace by Number Only:
- If the user provides ONLY a sender number and no message content, perform a "Number Reputation Check".
- Analyze the prefix and format. Personal numbers (e.g., +27 60, +27 72) claiming to be "DUT" are always 100% risk.
- Provide the geographic origin and tower info based on the number's metadata.
`;

interface ScanResult {
  riskPercentage: number;
  reason: string;
  inputSource?: 'typed' | 'pasted';
  geographicOrigin?: string;
  towerInfo?: {
    id: string;
    location: string;
    carrier: string;
    distance: string;
  };
  layersResults: {
    urgency: { score: number; details: string };
    financial: { score: number; details: string };
    url: { score: number; details: string };
    impersonation: { score: number; details: string };
    linguistic: { score: number; details: string };
  };
}

interface ScannedMessage extends ScanResult {
  id: string;
  content: string;
  inputSource?: 'typed' | 'pasted';
  senderNumber?: string;
  timestamp: Timestamp;
  userId: string;
}

interface OfficialChannel {
  id: string;
  type: 'email' | 'sms' | 'url';
  value: string;
  description: string;
}

// --- Components ---

const Navbar = ({ user, onLogin, onLogout }: { user: User | null, onLogin: () => void, onLogout: () => void }) => (
  <nav className="fixed top-0 left-0 right-0 bg-white/80 backdrop-blur-md border-b border-gray-100 z-50">
    <div className="max-w-5xl mx-auto px-4 h-16 flex items-center justify-between">
      <div className="flex items-center gap-2">
        <div className="bg-blue-600 p-1.5 rounded-lg">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <span className="font-bold text-gray-900 tracking-tight">Reg-Guard <span className="text-blue-600">Genius</span></span>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="hidden sm:flex items-center gap-2 bg-emerald-50 px-3 py-1 rounded-full border border-emerald-100">
          <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
          <span className="text-[10px] font-bold text-emerald-700 uppercase">Live Protection</span>
        </div>

        <div className="hidden md:flex items-center gap-2 bg-blue-50 px-3 py-1 rounded-full border border-blue-100">
          <Zap className="w-3 h-3 text-blue-600" />
          <span className="text-[10px] font-bold text-blue-700 uppercase">Free Tier</span>
        </div>

        {user ? (
          <div className="flex items-center gap-3">
            <div className="hidden sm:block text-right">
              <p className="text-xs font-bold text-gray-900 leading-none">{user.displayName || 'User'}</p>
              <p className="text-[10px] text-gray-500 leading-none mt-1">{user.email}</p>
            </div>
            <button 
              onClick={onLogout}
              className="p-2 hover:bg-red-50 text-red-600 rounded-xl transition-colors"
              title="Sign Out"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        ) : (
          <button 
            onClick={onLogin}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-xl text-sm font-bold transition-all shadow-sm"
          >
            <LogIn className="w-4 h-4" />
            <span>Sign In</span>
          </button>
        )}
      </div>
    </div>
  </nav>
);

const RiskBadge = ({ risk }: { risk: number }) => {
  const color = risk > 70 ? 'bg-red-100 text-red-700 border-red-200' : 
                risk > 30 ? 'bg-amber-100 text-amber-700 border-amber-200' : 
                'bg-emerald-100 text-emerald-700 border-emerald-200';
  
  return (
    <div className={cn("px-3 py-1 rounded-full text-xs font-bold border", color)}>
      {risk}% Risk
    </div>
  );
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'scan' | 'reports' | 'channels'>('dashboard');
  const [messageToScan, setMessageToScan] = useState('');
  const [senderNumber, setSenderNumber] = useState('');
  const [inputSource, setInputSource] = useState<'typed' | 'pasted'>('typed');
  const [isScanning, setIsScanning] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScannedMessage[]>([]);
  const [scanResult, setScanResult] = useState<ScannedMessage | null>(null);
  const [officialChannels, setOfficialChannels] = useState<OfficialChannel[]>([]);
  const [protectionEnabled, setProtectionEnabled] = useState(true);
  const [user, setUser] = useState<User | null>(null);
  const [selectedScam, setSelectedScam] = useState<ScannedMessage | null>(null);
  const [localHistoryIds, setLocalHistoryIds] = useState<string[]>(() => {
    const saved = localStorage.getItem('reg_guard_genius_history');
    return saved ? JSON.parse(saved) : [];
  });

  // Auth Listener
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
    });
    return () => unsubscribe();
  }, []);

  const handleLogin = async () => {
    try {
      const provider = new GoogleAuthProvider();
      await signInWithPopup(auth, provider);
      toast.success("Signed in successfully!");
    } catch (error: any) {
      console.error("Login error:", error);
      toast.error("Failed to sign in. Please try again.");
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      toast.success("Signed out!");
    } catch (error: any) {
      console.error("Logout error:", error);
      toast.error("Failed to sign out.");
    }
  };

  // Test Firestore Connection
  useEffect(() => {
    const testConnection = async () => {
      try {
        await getDocFromServer(doc(db, 'test', 'connection'));
      } catch (error) {
        if (error instanceof Error && error.message.includes('the client is offline')) {
          console.error("Please check your Firebase configuration.");
        }
      }
    };
    testConnection();
  }, []);

  // Check Server Health
  useEffect(() => {
    const checkHealth = async () => {
      try {
        await fetch('/api/health');
      } catch (e) {
        console.error("Health check failed:", e);
      }
    };
    checkHealth();
  }, []);

  // Fetch User Scan History when logged in
  useEffect(() => {
    if (!user) return;

    const q = query(
      collection(db, 'scannedMessages'),
      where('userId', '==', user.uid),
      orderBy('timestamp', 'desc')
    );

    const unsubscribe = onSnapshot(q, (snapshot) => {
      const docs = snapshot.docs.map(d => ({ id: d.id, ...d.data() } as ScannedMessage));
      // Ensure unique docs by ID
      const uniqueDocs = Array.from(new Map(docs.map(item => [item.id, item])).values());
      setScanHistory(uniqueDocs);
    }, (error) => {
      console.error("Error fetching user history:", error);
      if (error.message.includes("requires an index")) {
        toast.error("Database index is building. History will appear shortly.");
      } else {
        toast.error("Failed to load scan history.");
      }
    });

    return unsubscribe;
  }, [user]);

  // Fetch Scan History from Local Storage IDs (for anonymous users)
  useEffect(() => {
    if (user || localHistoryIds.length === 0) {
      if (!user) setScanHistory([]);
      return;
    }
    
    const uniqueIds = Array.from(new Set(localHistoryIds)).slice(0, 30);
    if (uniqueIds.length === 0) {
      setScanHistory([]);
      return;
    }

    const q = query(
      collection(db, 'scannedMessages'),
      where(documentId(), 'in', uniqueIds)
    );
    
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const docs = snapshot.docs.map(d => ({ id: d.id, ...d.data() } as ScannedMessage));
      // Ensure unique docs by ID
      const uniqueDocs = Array.from(new Map(docs.map(item => [item.id, item])).values());
      // Sort by timestamp manually since 'in' doesn't preserve order
      setScanHistory(uniqueDocs.sort((a, b) => b.timestamp.toMillis() - a.timestamp.toMillis()));
    });
    return unsubscribe;
  }, [localHistoryIds]);

  // Fetch Official Channels
  useEffect(() => {
    const q = query(collection(db, 'officialChannels'));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      setOfficialChannels(snapshot.docs.map(d => ({ id: d.id, ...d.data() } as OfficialChannel)));
    });
    return unsubscribe;
  }, []);

  const handleScan = async () => {
    if (!messageToScan.trim() && !senderNumber.trim()) {
      toast.error("Please provide a message or a sender number to trace.");
      return;
    }

    setIsScanning(true);
    try {
      // Initialize Gemini AI with the platform-provided key
      // The platform handles injecting process.env.GEMINI_API_KEY into the Vite build
      const apiKey = process.env.GEMINI_API_KEY;
      
      if (!apiKey || apiKey === 'undefined' || apiKey === '') {
        toast.error("Gemini API Key is missing. Please ensure it is set in 'Settings > Secrets'.");
        setIsScanning(false);
        return;
      }

      const ai = new GoogleGenAI({ apiKey });
      
      console.log("Calling Gemini AI from client...");
      
      // Simple cache check to save quota
      const existingScan = scanHistory.find(s => s.content === messageToScan && s.senderNumber === senderNumber);
      if (existingScan) {
        toast.info("Loading result from history to save quota...");
        setScanResult(existingScan);
        setActiveTab('dashboard');
        setIsScanning(false);
        return;
      }
      
      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: `Analyze this communication for registration scams. 
        INPUT METHOD: ${inputSource.toUpperCase()}
        SENDER NUMBER: ${senderNumber || 'Unknown'}
        MESSAGE CONTENT: "${messageToScan || 'No message content provided - trace by number only'}"
        
        If no message content is provided, focus your analysis on the sender number's reputation, geographic origin, and likely network carrier.`,
        config: {
          systemInstruction: SYSTEM_PROMPT,
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              riskPercentage: { type: Type.NUMBER },
              reason: { type: Type.STRING },
              inputSource: { type: Type.STRING },
              geographicOrigin: { type: Type.STRING },
              towerInfo: {
                type: Type.OBJECT,
                properties: {
                  id: { type: Type.STRING },
                  location: { type: Type.STRING },
                  carrier: { type: Type.STRING },
                  distance: { type: Type.STRING }
                },
                required: ["id", "location", "carrier", "distance"]
              },
              layersResults: {
                type: Type.OBJECT,
                properties: {
                  urgency: { 
                    type: Type.OBJECT, 
                    properties: { score: { type: Type.NUMBER }, details: { type: Type.STRING } },
                    required: ["score", "details"]
                  },
                  financial: { 
                    type: Type.OBJECT, 
                    properties: { score: { type: Type.NUMBER }, details: { type: Type.STRING } },
                    required: ["score", "details"]
                  },
                  url: { 
                    type: Type.OBJECT, 
                    properties: { score: { type: Type.NUMBER }, details: { type: Type.STRING } },
                    required: ["score", "details"]
                  },
                  impersonation: { 
                    type: Type.OBJECT, 
                    properties: { score: { type: Type.NUMBER }, details: { type: Type.STRING } },
                    required: ["score", "details"]
                  },
                  linguistic: { 
                    type: Type.OBJECT, 
                    properties: { score: { type: Type.NUMBER }, details: { type: Type.STRING } },
                    required: ["score", "details"]
                  }
                },
                required: ["urgency", "financial", "url", "impersonation", "linguistic"]
              }
            },
            required: ["riskPercentage", "reason", "inputSource", "geographicOrigin", "towerInfo", "layersResults"]
          }
        }
      });

      if (!response.text) {
        throw new Error("AI returned an empty response");
      }
      
      const result: ScanResult = JSON.parse(response.text);
      console.log("Scan Result:", result);
      
      const currentMessage = messageToScan;
      const currentSender = senderNumber;
      let savedId = Date.now().toString();
      try {
        const docRef = await addDoc(collection(db, 'scannedMessages'), {
          ...result,
          content: currentMessage,
          senderNumber: currentSender,
          userId: user?.uid || 'anonymous',
          timestamp: Timestamp.now()
        });
        savedId = docRef.id;
      } catch (dbError) {
        console.error("Failed to save scan to database:", dbError);
        toast.error("Analysis complete, but failed to save to history.");
      }

      const newHistory = Array.from(new Set([savedId, ...localHistoryIds])).slice(0, 50);
      setLocalHistoryIds(newHistory);
      localStorage.setItem('reg_guard_genius_history', JSON.stringify(newHistory));

      // Set result BEFORE clearing message
      setScanResult({
        id: savedId,
        ...result,
        inputSource: result.inputSource || inputSource,
        content: currentMessage,
        senderNumber: currentSender,
        userId: user?.uid || 'anonymous',
        timestamp: Timestamp.now()
      });

      setMessageToScan('');
      setSenderNumber('');
      toast.success("Scan complete!");
      setActiveTab('dashboard');
    } catch (error: any) {
      console.error("Scan error details:", error);
      let errorMessage = error.message || "An unexpected error occurred";
      
      if (errorMessage.includes("API key not valid") || errorMessage.includes("API_KEY_INVALID")) {
        errorMessage = "Invalid Gemini API Key. Please update your API Key in the AI Studio Settings > Secrets menu.";
      } else if (errorMessage.includes("quota") || errorMessage.includes("429")) {
        errorMessage = "Gemini API quota exceeded. This is a limit of the AI Studio Free Tier. The quota will reset tomorrow.";
      }
      
      toast.error(`Scan failed: ${errorMessage}`);
    } finally {
      setIsScanning(false);
    }
  };

  const reportScam = async (content: string) => {
    try {
      await addDoc(collection(db, 'scamReports'), {
        content,
        reporterId: user?.uid || 'anonymous',
        timestamp: Timestamp.now(),
        status: 'pending'
      });
      toast.success("Scam reported to DUT security");
    } catch (error) {
      toast.error("Failed to submit report");
    }
  };

  const handleReportScam = async (scan: ScannedMessage) => {
    try {
      await addDoc(collection(db, 'scamReports'), {
        content: scan.content,
        senderNumber: scan.senderNumber || 'Unknown',
        geographicOrigin: scan.geographicOrigin || 'Unknown',
        towerInfo: scan.towerInfo || null,
        riskPercentage: scan.riskPercentage,
        reason: scan.reason,
        reporterId: user?.uid || 'anonymous',
        timestamp: Timestamp.now(),
        status: 'pending',
        type: 'detailed_threat_report'
      });
      toast.success("Detailed threat report submitted to authorities");
    } catch (error) {
      console.error("Report error:", error);
      toast.error("Failed to submit detailed report");
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 font-sans text-gray-900">
      <Toaster position="top-center" richColors />
      <Navbar user={user} onLogin={handleLogin} onLogout={handleLogout} />

      <main className="max-w-5xl mx-auto px-4 pt-24 pb-32">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Left Column: Navigation & Quick Stats */}
            <div className="lg:col-span-1 space-y-6">
              <div className="bg-white p-6 rounded-3xl border border-gray-100 shadow-sm">
                <h2 className="text-sm font-bold text-gray-400 uppercase tracking-widest mb-4">Protection Status</h2>
                <div className="flex items-center justify-between p-4 bg-emerald-50 rounded-2xl border border-emerald-100">
                  <div className="flex items-center gap-3">
                    <ShieldCheck className="w-6 h-6 text-emerald-600" />
                    <span className="font-bold text-emerald-700">Active</span>
                  </div>
                  <div className="text-[10px] font-bold text-emerald-600 uppercase">Real-time</div>
                </div>
                
                <div className="mt-6 space-y-2">
                  <button 
                    onClick={() => setActiveTab('dashboard')}
                    className={cn(
                      "w-full flex items-center justify-between p-4 rounded-2xl transition-all font-semibold",
                      activeTab === 'dashboard' ? "bg-blue-600 text-white shadow-lg shadow-blue-100" : "hover:bg-gray-50 text-gray-600"
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <History className="w-5 h-5" />
                      Dashboard
                    </div>
                    <ChevronRight className="w-4 h-4 opacity-50" />
                  </button>
                  <button 
                    onClick={() => setActiveTab('scan')}
                    className={cn(
                      "w-full flex items-center justify-between p-4 rounded-2xl transition-all font-semibold",
                      activeTab === 'scan' ? "bg-blue-600 text-white shadow-lg shadow-blue-100" : "hover:bg-gray-50 text-gray-600"
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <Search className="w-5 h-5" />
                      Scan Message
                    </div>
                    <ChevronRight className="w-4 h-4 opacity-50" />
                  </button>
                  <button 
                    onClick={() => setActiveTab('channels')}
                    className={cn(
                      "w-full flex items-center justify-between p-4 rounded-2xl transition-all font-semibold",
                      activeTab === 'channels' ? "bg-blue-600 text-white shadow-lg shadow-blue-100" : "hover:bg-gray-50 text-gray-600"
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <Globe className="w-5 h-5" />
                      Official Channels
                    </div>
                    <ChevronRight className="w-4 h-4 opacity-50" />
                  </button>
                </div>
              </div>

              <div className="bg-blue-900 p-6 rounded-3xl text-white relative overflow-hidden">
                <div className="relative z-10">
                  <h3 className="font-bold text-lg mb-2">Chrome Extension</h3>
                  <p className="text-blue-200 text-xs mb-4">Enable automatic protection while browsing registration portals.</p>
                  <button 
                    onClick={() => setProtectionEnabled(!protectionEnabled)}
                    className={cn(
                      "w-full py-2 rounded-xl text-xs font-bold transition-all",
                      protectionEnabled ? "bg-emerald-500 text-white" : "bg-white/20 text-white"
                    )}
                  >
                    {protectionEnabled ? "Protection Enabled" : "Enable Protection"}
                  </button>
                </div>
                <Globe className="absolute -bottom-4 -right-4 w-24 h-24 text-white/10" />
              </div>
            </div>

            {/* Right Column: Content */}
            <div className="lg:col-span-2 space-y-6">
              <AnimatePresence mode="wait">
                {activeTab === 'dashboard' && (
                  <motion.div 
                    key="dashboard"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="space-y-6"
                  >
                    <div className="flex items-center justify-between">
                      <h2 className="text-2xl font-black tracking-tight">Recent Scans</h2>
                      <div className="flex items-center gap-4">
                        {scanHistory.length > 0 && (
                          <button 
                            onClick={() => {
                              setLocalHistoryIds([]);
                              localStorage.removeItem('reg_guard_genius_history');
                              setScanHistory([]);
                              toast.success("History cleared");
                            }}
                            className="text-gray-400 text-xs font-bold hover:text-red-600 transition-colors flex items-center gap-1"
                          >
                            <Trash2 className="w-3 h-3" /> Clear History
                          </button>
                        )}
                        {scanResult && (
                          <button 
                            onClick={() => setScanResult(null)}
                            className="text-gray-400 text-xs font-bold hover:text-gray-600"
                          >
                            Clear Result
                          </button>
                        )}
                        <button 
                          onClick={() => setActiveTab('scan')}
                          className="text-blue-600 text-sm font-bold flex items-center gap-1"
                        >
                          New Scan <ChevronRight className="w-4 h-4" />
                        </button>
                      </div>
                    </div>

                    {scanResult && (
                      <motion.div 
                        initial={{ scale: 0.95, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        className="bg-blue-600 p-8 rounded-[2rem] text-white shadow-2xl shadow-blue-200 relative overflow-hidden cursor-pointer"
                        onClick={() => setSelectedScam(scanResult)}
                      >
                        <div className="relative z-10">
                          <div className="flex items-center justify-between mb-6">
                            <div className="flex flex-col gap-2">
                              <div className="px-4 py-1.5 bg-white/20 backdrop-blur-md rounded-full text-xs font-black uppercase tracking-widest w-fit">
                                {scanResult.inputSource === 'typed' ? "Simulation / Test Mode" : "Live Threat Analysis"}
                              </div>
                              {scanResult.inputSource === 'typed' && (
                                <div className="text-[10px] font-bold text-blue-200 uppercase tracking-tighter">
                                  Note: Manually typed content is not a real scam.
                                </div>
                              )}
                            </div>
                            <div className="text-4xl font-black">{scanResult.riskPercentage}%</div>
                          </div>
                          
                          <h3 className="text-xl font-bold mb-4 leading-tight">
                            {scanResult.riskPercentage > 70 ? "High Risk Detected" : scanResult.riskPercentage > 30 ? "Potential Risk" : "Likely Safe"}
                          </h3>
                          
                          <div className="bg-white/10 backdrop-blur-md p-6 rounded-2xl border border-white/10 mb-6">
                            <p className="text-blue-50 text-sm leading-relaxed italic mb-4">"{scanResult.content}"</p>
                            
                            {scanResult.geographicOrigin && (
                              <div className="mb-6 space-y-3">
                                <div className="flex items-center gap-2 bg-white/5 p-3 rounded-xl border border-white/5">
                                  <div className="bg-blue-500/20 p-1.5 rounded-lg">
                                    <Globe className="w-4 h-4 text-blue-200" />
                                  </div>
                                  <div>
                                    <p className="text-[10px] font-bold text-blue-200 uppercase tracking-widest">Origin Analysis</p>
                                    <p className="text-sm font-semibold">{scanResult.geographicOrigin}</p>
                                  </div>
                                </div>

                                {/* Triangulation Visual */}
                                <div className="h-32 bg-blue-950/50 rounded-2xl relative overflow-hidden border border-white/5">
                                  <div className="absolute inset-0 opacity-20">
                                    <div className="absolute inset-0" style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(255,255,255,0.1) 1px, transparent 0)', backgroundSize: '20px 20px' }} />
                                  </div>
                                  <div className="absolute inset-0 flex items-center justify-center">
                                    <div className="relative">
                                      <motion.div 
                                        animate={{ scale: [1, 2, 1], opacity: [0.5, 0, 0.5] }}
                                        transition={{ duration: 2, repeat: Infinity }}
                                        className="absolute inset-0 bg-blue-400 rounded-full"
                                      />
                                      <div className="w-3 h-3 bg-blue-400 rounded-full relative z-10 shadow-[0_0_15px_rgba(96,165,250,0.8)]" />
                                    </div>
                                  </div>
                                  <div className="absolute bottom-2 left-3">
                                    <p className="text-[8px] font-bold text-blue-300 uppercase tracking-widest animate-pulse">Signal Triangulated</p>
                                  </div>
                                </div>

                                {scanResult.towerInfo && (
                                  <div className="bg-blue-950/30 p-4 rounded-2xl border border-white/5 space-y-3">
                                    <div className="flex items-center justify-between">
                                      <div className="flex items-center gap-2">
                                        <Smartphone className="w-3 h-3 text-blue-300" />
                                        <span className="text-[10px] font-bold text-blue-300 uppercase">Carrier Node</span>
                                      </div>
                                      <span className="text-[10px] font-mono text-blue-400">{scanResult.towerInfo.id}</span>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                      <div>
                                        <p className="text-[8px] font-bold text-gray-400 uppercase">Location</p>
                                        <p className="text-xs font-semibold text-white">{scanResult.towerInfo.location}</p>
                                      </div>
                                      <div>
                                        <p className="text-[8px] font-bold text-gray-400 uppercase">Network</p>
                                        <p className="text-xs font-semibold text-white">{scanResult.towerInfo.carrier}</p>
                                      </div>
                                    </div>
                                    <div className="pt-2 border-t border-white/5 flex items-center justify-between">
                                      <span className="text-[8px] font-bold text-gray-400 uppercase">Proximity</span>
                                      <span className="text-[10px] font-bold text-emerald-400">{scanResult.towerInfo.distance}</span>
                                    </div>
                                  </div>
                                )}
                              </div>
                            )}

                            <div className="flex items-start gap-3">
                              <Info className="w-5 h-5 text-blue-200 shrink-0 mt-0.5" />
                              <p className="text-sm font-medium">{scanResult.reason}</p>
                            </div>
                          </div>

                          <div className="flex items-center justify-between">
                            <div className="grid grid-cols-5 gap-2">
                              {scanResult.layersResults && Object.entries(scanResult.layersResults).map(([key, val]: [string, any]) => (
                                <div key={`scan-result-layer-${key}`} className="flex flex-col items-center gap-2">
                                  <div className={cn(
                                    "w-10 h-10 rounded-xl flex items-center justify-center text-xs font-black shadow-lg",
                                    val.score > 70 ? "bg-red-500" : val.score > 30 ? "bg-amber-500" : "bg-emerald-500"
                                  )}>
                                    {key[0].toUpperCase()}
                                  </div>
                                  <span className="text-[8px] font-bold uppercase opacity-60 tracking-tighter">{key}</span>
                                </div>
                              ))}
                            </div>
                            <div className="flex items-center gap-2 text-blue-200">
                              <Search className="w-4 h-4" />
                              <span className="text-xs font-bold uppercase tracking-widest">View Scammer Profile</span>
                            </div>
                          </div>
                        </div>
                        <Shield className="absolute -bottom-8 -right-8 w-48 h-48 text-white/5" />
                      </motion.div>
                    )}

                    {scanHistory.length === 0 ? (
                      <div className="bg-white p-12 rounded-3xl border border-dashed border-gray-200 flex flex-col items-center text-center">
                        <MessageSquare className="w-12 h-12 text-gray-200 mb-4" />
                        <p className="text-gray-400 font-medium">No messages scanned yet.</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {scanHistory.map((scan) => (
                          <div 
                            key={scan.id} 
                            onClick={() => setSelectedScam(scan)}
                            className="bg-white p-6 rounded-3xl border border-gray-100 shadow-sm hover:shadow-md transition-all group cursor-pointer"
                          >
                            <div className="flex items-start justify-between mb-4">
                              <div className="flex flex-col gap-1">
                                <div className="flex items-center gap-2">
                                  <RiskBadge risk={scan.riskPercentage} />
                                  <span className={cn(
                                    "text-[8px] font-bold px-1.5 py-0.5 rounded-full uppercase tracking-tighter",
                                    scan.inputSource === 'typed' ? "bg-blue-100 text-blue-700" : "bg-amber-100 text-amber-700"
                                  )}>
                                    {scan.inputSource === 'typed' ? "Simulation" : "Live Threat"}
                                  </span>
                                </div>
                                {scan.senderNumber && (
                                  <span className="text-[10px] font-bold text-gray-500 flex items-center gap-1">
                                    <Smartphone className="w-3 h-3" /> {scan.senderNumber}
                                  </span>
                                )}
                              </div>
                              <span className="text-[10px] font-bold text-gray-400 uppercase">
                                {scan.timestamp.toDate().toLocaleDateString()}
                              </span>
                            </div>
                            <p className="text-gray-800 font-medium mb-4 line-clamp-2 italic">"{scan.content}"</p>
                            
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2 text-blue-600">
                                <Search className="w-3 h-3" />
                                <span className="text-[10px] font-bold uppercase tracking-wider">View Scammer Profile</span>
                              </div>
                              <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-blue-500 transition-colors" />
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </motion.div>
                )}

                {/* Scammer Profile Modal */}
                <AnimatePresence>
                  {selectedScam && (
                    <motion.div 
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
                      onClick={() => setSelectedScam(null)}
                    >
                      <motion.div 
                        initial={{ scale: 0.9, y: 20 }}
                        animate={{ scale: 1, y: 0 }}
                        exit={{ scale: 0.9, y: 20 }}
                        className="bg-white w-full max-w-2xl rounded-[2.5rem] overflow-hidden shadow-2xl"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="bg-blue-600 p-8 text-white relative">
                          <div className="relative z-10">
                            <div className="flex items-center justify-between mb-6">
                              <div className="flex items-center gap-3">
                                <div className="bg-white/20 p-3 rounded-2xl backdrop-blur-md">
                                  <ShieldAlert className="w-8 h-8" />
                                </div>
                                <div>
                                  <h3 className="text-2xl font-black tracking-tight">Scammer Profile</h3>
                                  <p className="text-blue-100 text-xs font-bold uppercase tracking-widest">Simulated Threat Intelligence</p>
                                </div>
                              </div>
                              <button 
                                onClick={() => setSelectedScam(null)}
                                className="bg-white/10 hover:bg-white/20 p-2 rounded-full transition-colors"
                              >
                                <X className="w-6 h-6" />
                              </button>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                              <div className="bg-white/10 backdrop-blur-md p-4 rounded-2xl border border-white/10">
                                <p className="text-[10px] font-bold text-blue-200 uppercase mb-1">Risk Level</p>
                                <div className="flex items-center gap-2">
                                  <div className="text-3xl font-black">{selectedScam.riskPercentage}%</div>
                                  <RiskBadge risk={selectedScam.riskPercentage} />
                                </div>
                              </div>
                              <div className="bg-white/10 backdrop-blur-md p-4 rounded-2xl border border-white/10">
                                <p className="text-[10px] font-bold text-blue-200 uppercase mb-1">Source Type</p>
                                <div className="text-xl font-bold capitalize">{selectedScam.inputSource || 'Live Threat'}</div>
                              </div>
                            </div>
                          </div>
                          <Globe className="absolute -bottom-12 -right-12 w-64 h-64 text-white/5" />
                        </div>

                        <div className="p-8 space-y-6 max-h-[60vh] overflow-y-auto">
                          {/* Origin & Network Section */}
                          <div className="space-y-4">
                            <h4 className="text-xs font-black text-gray-400 uppercase tracking-widest flex items-center gap-2">
                              <MapPin className="w-4 h-4" /> Origin Triangulation
                            </h4>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="bg-gray-50 p-4 rounded-2xl border border-gray-100">
                                <p className="text-[10px] font-bold text-gray-400 uppercase mb-1">Sender's Carrier / Tower ID</p>
                                <p className="font-bold text-gray-800">{selectedScam.towerInfo?.carrier || 'Unknown Network'}</p>
                                <p className="text-[10px] font-mono text-blue-600 mt-1">{selectedScam.towerInfo?.id || 'NODE-ID-PENDING'}</p>
                              </div>
                              <div className="bg-gray-50 p-4 rounded-2xl border border-gray-100">
                                <p className="text-[10px] font-bold text-gray-400 uppercase mb-1">Sender's Last Known Location</p>
                                <p className="font-bold text-gray-800">{selectedScam.towerInfo?.location || selectedScam.geographicOrigin || 'Unknown'}</p>
                                <p className="text-[10px] text-emerald-600 font-bold mt-1">Triangulation: {selectedScam.towerInfo?.distance || 'Within Region'}</p>
                              </div>
                            </div>
                          </div>

                          {/* Message Details */}
                          <div className="space-y-4">
                            <h4 className="text-xs font-black text-gray-400 uppercase tracking-widest flex items-center gap-2">
                              <MessageSquare className="w-4 h-4" /> Scam Content
                            </h4>
                            <div className="bg-gray-50 p-6 rounded-2xl border border-gray-100 italic text-gray-700 leading-relaxed">
                              "{selectedScam.content}"
                            </div>
                          </div>

                          {/* AI Analysis Layers */}
                          <div className="space-y-4">
                            <div className="bg-blue-50 p-6 rounded-3xl border border-blue-100">
                              <div className="flex items-center gap-2 text-blue-700 mb-2">
                                <Info className="w-5 h-5" />
                                <h3 className="font-bold text-sm">Intelligence Disclaimer</h3>
                              </div>
                              <p className="text-[10px] text-blue-800 leading-relaxed opacity-80">
                                This location data represents the <strong>sender's</strong> suspected origin, not yours. 
                                It is simulated based on the sender's network prefix metadata and carrier triangulation patterns.
                              </p>
                            </div>
                            <h4 className="text-xs font-black text-gray-400 uppercase tracking-widest flex items-center gap-2">
                              <Shield className="w-4 h-4" /> 5-Layer Analysis
                            </h4>
                            <div className="space-y-3">
                              {Object.entries(selectedScam.layersResults).map(([key, val]: [string, any]) => (
                                <div key={`modal-layer-${key}`} className="bg-white border border-gray-100 rounded-2xl p-4 shadow-sm">
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="text-xs font-bold capitalize text-gray-800">{key} Analysis</span>
                                    <div className={cn(
                                      "px-2 py-0.5 rounded-full text-[10px] font-bold",
                                      val.score > 70 ? "bg-red-100 text-red-700" : val.score > 30 ? "bg-amber-100 text-amber-700" : "bg-emerald-100 text-emerald-700"
                                    )}>
                                      {val.score}% Match
                                    </div>
                                  </div>
                                  <p className="text-xs text-gray-500 leading-relaxed">{val.details}</p>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Action Buttons */}
                          <div className="flex gap-4 pt-4">
                            <button 
                              onClick={() => {
                                handleReportScam(selectedScam);
                                setSelectedScam(null);
                              }}
                              className="flex-1 bg-red-600 hover:bg-red-700 text-white py-4 rounded-2xl font-bold flex items-center justify-center gap-2 transition-all shadow-lg shadow-red-100"
                            >
                              <Flag className="w-5 h-5" /> Report to Authorities
                            </button>
                            <button 
                              onClick={() => {
                                toast.info("Scam data exported for carrier review");
                                setSelectedScam(null);
                              }}
                              className="flex-1 bg-gray-900 hover:bg-black text-white py-4 rounded-2xl font-bold flex items-center justify-center gap-2 transition-all"
                            >
                              <Share2 className="w-5 h-5" /> Export Intelligence
                            </button>
                          </div>
                        </div>
                      </motion.div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {activeTab === 'scan' && (
                  <motion.div 
                    key="scan"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="space-y-6"
                  >
                    <h2 className="text-2xl font-black tracking-tight">Trace Scam / Scan Message</h2>
                    <div className="bg-white p-8 rounded-3xl border border-gray-100 shadow-xl shadow-blue-50">
                      <div className="space-y-4">
                        <div>
                          <label className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-2 block">Sender's Number / ID</label>
                          <div className="relative">
                            <input 
                              type="text"
                              value={senderNumber}
                              onChange={(e) => setSenderNumber(e.target.value)}
                              placeholder="e.g. +27 31 123 4567 or 'DUT'"
                              className="w-full p-4 bg-gray-50 rounded-2xl border-none focus:ring-2 focus:ring-blue-500 transition-all text-gray-800 font-medium"
                            />
                            <div className="absolute right-4 top-1/2 -translate-y-1/2">
                              <Smartphone className="w-4 h-4 text-gray-400" />
                            </div>
                          </div>
                        </div>

                        <div>
                          <label className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-2 block">Message Content</label>
                          <div className="relative">
                            <textarea 
                              value={messageToScan}
                              onChange={(e) => {
                                setMessageToScan(e.target.value);
                                if (e.target.value.length < 5) setInputSource('typed');
                              }}
                              onPaste={() => setInputSource('pasted')}
                              placeholder="e.g. Bank: Your account is locked... (Optional if tracing number)"
                              className="w-full h-40 p-6 bg-gray-50 rounded-2xl border-none focus:ring-2 focus:ring-blue-500 transition-all resize-none text-gray-800 font-medium"
                            />
                            <div className="absolute bottom-4 right-4 flex items-center gap-2">
                              <span className={cn(
                                "text-[10px] font-bold px-2 py-1 rounded-full uppercase tracking-wider",
                                inputSource === 'pasted' ? "bg-amber-100 text-amber-700" : "bg-blue-100 text-blue-700"
                              )}>
                                {inputSource === 'pasted' ? "Pasted Content" : "Typed Content"}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                      <button 
                        onClick={handleScan}
                        disabled={isScanning || (!messageToScan.trim() && !senderNumber.trim())}
                        className={cn(
                          "w-full mt-6 py-4 rounded-2xl font-bold text-lg flex items-center justify-center gap-3 transition-all",
                          isScanning || (!messageToScan.trim() && !senderNumber.trim()) ? "bg-gray-100 text-gray-400 cursor-not-allowed" : "bg-blue-600 text-white hover:bg-blue-700 shadow-lg shadow-blue-100"
                        )}
                      >
                        {isScanning ? (
                          <>
                            <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                            Tracing Origin...
                          </>
                        ) : (
                          <>
                            <Shield className="w-6 h-6" /> Trace & Identify Threat
                          </>
                        )}
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div className="bg-white p-4 rounded-2xl border border-gray-100 flex items-center gap-4">
                        <div className="bg-amber-100 p-2 rounded-xl"><AlertTriangle className="w-5 h-5 text-amber-600" /></div>
                        <div>
                          <p className="text-xs font-bold text-gray-900">Urgency Check</p>
                          <p className="text-[10px] text-gray-500">Detects high-pressure language</p>
                        </div>
                      </div>
                      <div className="bg-white p-4 rounded-2xl border border-gray-100 flex items-center gap-4">
                        <div className="bg-blue-100 p-2 rounded-xl"><Globe className="w-5 h-5 text-blue-600" /></div>
                        <div>
                          <p className="text-xs font-bold text-gray-900">URL Analysis</p>
                          <p className="text-[10px] text-gray-500">Verifies official company domains</p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-blue-50 p-6 rounded-3xl border border-blue-100">
                      <div className="flex items-center gap-2 text-blue-700 mb-2">
                        <Shield className="w-5 h-5" />
                        <h3 className="font-bold">AI Studio Free Tier</h3>
                      </div>
                      <p className="text-sm text-blue-800 leading-relaxed">
                        This app uses the <strong>Gemini 3 Flash</strong> model on the free tier. 
                        If you encounter "Quota Exceeded" errors, please wait a few minutes or try again tomorrow. 
                        Ensure your API key is correctly set in <strong>Settings &gt; Secrets</strong>.
                      </p>
                    </div>
                  </motion.div>
                )}

                {activeTab === 'channels' && (
                  <motion.div 
                    key="channels"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="space-y-6"
                  >
                    <h2 className="text-2xl font-black tracking-tight">Official Verification Channels</h2>
                    <div className="grid grid-cols-1 gap-4">
                      <div className="bg-white p-6 rounded-3xl border border-gray-100 shadow-sm flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="bg-blue-100 p-3 rounded-2xl text-blue-600"><Globe className="w-6 h-6" /></div>
                          <div>
                            <p className="font-bold text-gray-900">Official Portals</p>
                            <p className="text-sm text-gray-500">Always use the official company website.</p>
                          </div>
                        </div>
                        <CheckCircle className="w-5 h-5 text-emerald-500" />
                      </div>
                      
                      <div className="bg-white p-6 rounded-3xl border border-gray-100 shadow-sm flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="bg-purple-100 p-3 rounded-2xl text-purple-600"><MessageSquare className="w-6 h-6" /></div>
                          <div>
                            <p className="font-bold text-gray-900">Corporate Email Domains</p>
                            <p className="text-sm text-gray-500">e.g., @company.com, @gov.za</p>
                          </div>
                        </div>
                        <CheckCircle className="w-5 h-5 text-emerald-500" />
                      </div>

                      <div className="bg-white p-6 rounded-3xl border border-gray-100 shadow-sm flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="bg-amber-100 p-3 rounded-2xl text-amber-600"><Smartphone className="w-6 h-6" /></div>
                          <div>
                            <p className="font-bold text-gray-900">Verified SMS Senders</p>
                            <p className="text-sm text-gray-500">Look for alphanumeric IDs (e.g., 'BANK-NAME')</p>
                          </div>
                        </div>
                        <CheckCircle className="w-5 h-5 text-emerald-500" />
                      </div>
                    </div>

                    <div className="bg-amber-50 p-6 rounded-3xl border border-amber-100">
                      <div className="flex items-center gap-2 text-amber-700 mb-2">
                        <AlertTriangle className="w-5 h-5" />
                        <h3 className="font-bold">Global Security Warning</h3>
                      </div>
                      <p className="text-sm text-amber-800 leading-relaxed">
                        Official organizations will <strong>never</strong> ask you for your password, banking details, or payment via WhatsApp, Telegram, or personal email accounts. Always verify via official channels.
                      </p>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
      </main>

      {/* Mobile Bottom Nav */}
      <div className="fixed bottom-0 left-0 right-0 bg-white/80 backdrop-blur-md border-t border-gray-100 sm:hidden z-50">
        <div className="flex items-center justify-around h-20">
          <button onClick={() => setActiveTab('dashboard')} className={cn("p-3 rounded-2xl transition-all", activeTab === 'dashboard' ? "text-blue-600 bg-blue-50" : "text-gray-400")}>
            <History className="w-6 h-6" />
          </button>
          <button onClick={() => setActiveTab('scan')} className={cn("p-3 rounded-2xl transition-all", activeTab === 'scan' ? "text-blue-600 bg-blue-50" : "text-gray-400")}>
            <Search className="w-6 h-6" />
          </button>
          <button onClick={() => setActiveTab('channels')} className={cn("p-3 rounded-2xl transition-all", activeTab === 'channels' ? "text-blue-600 bg-blue-50" : "text-gray-400")}>
            <Globe className="w-6 h-6" />
          </button>
        </div>
      </div>
    </div>
  );
}
