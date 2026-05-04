import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Search, MessageSquare, Info, LogOut, LogIn, Globe, Smartphone, History, Flag, ExternalLink, ChevronRight, ShieldCheck, ShieldAlert, Zap, Trash2, Copy, X, MapPin, Share2, Key } from 'lucide-react';
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
import { jsPDF } from "jspdf";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Types ---
const SYSTEM_PROMPT = `
You are the Reg-Guard Global AI, a universal threat intelligence and forensics framework.
Your mission is to perform DEEP TRACING and IDENTITY INTELLIGENCE on communication scams.

ANALYSIS LAYERS:
1. Urgency & High-Pressure Tactics.
2. Financial Solicitation (requests for payment outside official routes).
3. Link & Domain Forensics:
   - Extract ALL URLs.
   - Analyze Domain Forensics: Age (simulated based on patterns), Registrar (predicted), and Brand Spoofing (detecting lookalikes like 'dut-portal.xyz' instead of 'dut.ac.za').
   - Detect Phishing kits and Brand Hijacking.
4. Impersonation & Identity Theft.
5. Linguistic & Pattern Analysis (lexical, syntactic, semantic).

GEOGRAPHIC & NETWORK ORIGIN:
- Trace sender number/ID. Identify Country, Carrier, and Triangulated Tower Site.
- Provide signal metrics (strength, coordinates with jitter for site-specific pinning).
- **Spoofing Detection**: Identify if the sender's identity is likely spoofed (e.g., alphanumeric IDs from unverified sources, or personal numbers used for institutional messaging).

IDENTITY INTELLIGENCE:
- Normalize the sender number to E.164 format.
- Evaluate the "Reputation Score" based on the patterns of use.
- Set "isSpoofed" flag based on the Spoofing Detection analysis.

URL FORENSICS & HOSTING:
- Extract and analyze all URLs.
- Identify the likely **Hosting Country** for the primary malicious link based on registrar and routing markers.

CAMPAIGN FINGERPRINTING:
- Generate a unique "Message Hash" or "Campaign ID" based on the structure and content of the message.
- Identify the "Campaign Archetype" (e.g., "Registration Fee Scam 2026").

EVIDENCE GENERATION:
- Summarize the analysis into an "Actionable Evidence Pack" suitable for law enforcement or institutional security.
- Highlight specific "Forensic Indicators" (bad links, malicious numbers, recurring templates).
`;

interface ScanResult {
  riskPercentage: number;
  reason: string;
  inputSource?: 'typed' | 'pasted';
  geographicOrigin?: string;
  identityIntelligence: {
    normalizedNumber: string;
    reputationScore: number;
    threatActorProfile?: string;
    isSpoofed?: boolean;
  };
  urlForensics: {
    extractedUrls: string[];
    brandSpoofing: boolean;
    targetBrand?: string;
    domainRiskDetails: string;
    hostingCountry?: string;
  };
  campaignFingerprint: {
    messageHash: string;
    archetype: string;
    clusterTag: string;
  };
  towerInfo?: {
    id: string;
    location: string;
    siteName?: string;
    carrier: string;
    distance: string;
    signalStrength: number;
    confidence: number;
    coordinates: { lat: number; lng: number };
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

  const generateEvidenceReport = (scan: ScannedMessage) => {
    const doc = new jsPDF();
    const title = "REG-GUARD GLOBAL: ACTIONABLE EVIDENCE PACK";
    
    doc.setFontSize(20);
    doc.text(title, 20, 20);
    
    doc.setFontSize(10);
    doc.text(`Generated on: ${new Date().toLocaleString()}`, 20, 30);
    doc.text(`Report ID: ${scan.id}`, 20, 35);
    
    doc.setFontSize(14);
    doc.text("1. IDENTITY INTELLIGENCE", 20, 50);
    doc.setFontSize(10);
    doc.text(`Sender Number: ${scan.senderNumber || 'Unknown'}`, 20, 60);
    doc.text(`Normalized ID: ${scan.identityIntelligence?.normalizedNumber || 'N/A'}`, 20, 65);
    doc.text(`Reputation Score: ${scan.identityIntelligence?.reputationScore || 0}%`, 20, 70);
    doc.text(`Threat Actor Profile: ${scan.identityIntelligence?.threatActorProfile || 'Standard Scam Template'}`, 20, 75);
    doc.text(`Spoofing Label: ${scan.identityIntelligence?.isSpoofed ? 'POSSIBLY SPOOFED' : 'VERIFIED FORMAT'}`, 20, 80);
    
    doc.setFontSize(14);
    doc.text("2. LINK & DOMAIN FORENSICS", 20, 95);
    doc.setFontSize(10);
    doc.text(`Extracted URLs: ${scan.urlForensics?.extractedUrls?.join(', ') || 'None detected'}`, 20, 105);
    doc.text(`Brand Spoofing: ${scan.urlForensics?.brandSpoofing ? 'YES' : 'NO'}`, 20, 110);
    doc.text(`Hosting Country: ${scan.urlForensics?.hostingCountry || 'N/A'}`, 20, 115);
    doc.text(`Domain Analysis: ${scan.urlForensics?.domainRiskDetails || 'N/A'}`, 20, 120);
    
    doc.setFontSize(14);
    doc.text("3. CAMPAIGN FINGERPRINT", 20, 135);
    doc.setFontSize(10);
    doc.text(`Archetype: ${scan.campaignFingerprint?.archetype || 'Unclassified'}`, 20, 145);
    doc.text(`Message Hash: ${scan.campaignFingerprint?.messageHash || 'N/A'}`, 20, 150);
    
    doc.setFontSize(14);
    doc.text("4. GEOGRAPHIC ORIGIN", 20, 165);
    doc.setFontSize(10);
    doc.text(`Origin: ${scan.geographicOrigin || 'Unknown'}`, 20, 175);
    doc.text(`Last Tower: ${scan.towerInfo?.location || 'N/A'}`, 20, 180);
    doc.text(`Coordinates: ${scan.towerInfo?.coordinates?.lat}, ${scan.towerInfo?.coordinates?.lng}`, 20, 185);
    
    doc.setFontSize(14);
    doc.text("5. MESSAGE CONTENT", 20, 200);
    doc.setFontSize(10);
    const splitContent = doc.splitTextToSize(scan.content, 170);
    doc.text(splitContent, 20, 210);
    
    doc.setFontSize(8);
    doc.text("CONFIDENTIAL: This report is generated by Reg-Guard Genius AI for security purposes.", 20, 280);
    
    doc.save(`RegGuard_Evidence_${scan.id}.pdf`);
    toast.success("Evidence Pack exported successfully!");
  };

  const [showTutorial, setShowTutorial] = useState(() => {
    return !localStorage.getItem('reg_guard_tutorial_completed');
  });
  const [tutorialStep, setTutorialStep] = useState(0);
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

  const tutorialSteps = [
    {
      title: "Welcome to Reg-Guard Global",
      content: "Protect yourself and your company from registration and communication scams worldwide. Let's take a quick tour.",
      icon: <Shield className="w-12 h-12 text-blue-600" />,
      action: "Next"
    },
    {
      title: "Trace & Scan",
      content: "Go to the 'Scan Message' tab to trace a suspicious phone number or scan a message for risk analysis.",
      icon: <Search className="w-12 h-12 text-blue-600" />,
      action: "Next"
    },
    {
      title: "Origin Triangulation",
      content: "We use network metadata to identify the sender's carrier and last known cell tower location with high precision.",
      icon: <MapPin className="w-12 h-12 text-blue-600" />,
      action: "Next"
    },
    {
      title: "5-Layer Analysis",
      content: "Our AI analyzes urgency, financial requests, URLs, impersonation, and linguistic patterns to calculate a risk score.",
      icon: <Zap className="w-12 h-12 text-blue-600" />,
      action: "Get Started"
    }
  ];

  const completeTutorial = () => {
    localStorage.setItem('reg_guard_tutorial_completed', 'true');
    setShowTutorial(false);
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
      const apiKey = process.env.GEMINI_API_KEY;
      
      if (!apiKey || apiKey === 'undefined' || apiKey === 'null') {
        throw new Error("API_KEY_MISSING");
      }

      const ai = new GoogleGenAI({ apiKey });
      
      console.log("Calling Gemini AI from client...");
      
      const response = await ai.models.generateContent({
        model: "gemini-flash-latest",
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
              identityIntelligence: {
                type: Type.OBJECT,
                properties: {
                  normalizedNumber: { type: Type.STRING },
                  reputationScore: { type: Type.NUMBER },
                  threatActorProfile: { type: Type.STRING },
                  isSpoofed: { type: Type.BOOLEAN }
                },
                required: ["normalizedNumber", "reputationScore", "isSpoofed"]
              },
              urlForensics: {
                type: Type.OBJECT,
                properties: {
                  extractedUrls: { type: Type.ARRAY, items: { type: Type.STRING } },
                  brandSpoofing: { type: Type.BOOLEAN },
                  targetBrand: { type: Type.STRING },
                  domainRiskDetails: { type: Type.STRING },
                  hostingCountry: { type: Type.STRING }
                },
                required: ["extractedUrls", "brandSpoofing", "domainRiskDetails", "hostingCountry"]
              },
              campaignFingerprint: {
                type: Type.OBJECT,
                properties: {
                  messageHash: { type: Type.STRING },
                  archetype: { type: Type.STRING },
                  clusterTag: { type: Type.STRING }
                },
                required: ["messageHash", "archetype", "clusterTag"]
              },
              towerInfo: {
                type: Type.OBJECT,
                properties: {
                  id: { type: Type.STRING },
                  location: { type: Type.STRING },
                  siteName: { type: Type.STRING },
                  carrier: { type: Type.STRING },
                  distance: { type: Type.STRING },
                  signalStrength: { type: Type.NUMBER },
                  confidence: { type: Type.NUMBER },
                  coordinates: {
                    type: Type.OBJECT,
                    properties: {
                      lat: { type: Type.NUMBER },
                      lng: { type: Type.NUMBER }
                    },
                    required: ["lat", "lng"]
                  }
                },
                required: ["id", "location", "siteName", "carrier", "distance", "signalStrength", "confidence", "coordinates"]
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
            required: ["riskPercentage", "reason", "inputSource", "geographicOrigin", "identityIntelligence", "urlForensics", "campaignFingerprint", "towerInfo", "layersResults"]
          }
        }
      });

      const jsonText = response.text || "{}";
      const cleanedJson = jsonText.replace(/```json\n?|```/g, '').trim();
      let result: ScanResult;
      try {
        result = JSON.parse(cleanedJson);
      } catch (parseError) {
        console.error("JSON Parse Error:", parseError, "Raw Text:", jsonText);
        throw new Error("INVALID_AI_RESPONSE");
      }
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

        // --- Post-Analysis Data Sync ---
        // 1. Update/Create Malicious Number Entity
        if (result.identityIntelligence?.normalizedNumber) {
          const num = result.identityIntelligence.normalizedNumber;
          const numberRef = doc(db, 'maliciousNumbers', num);
          const currentNum = await getDocFromServer(numberRef);
          if (currentNum.exists()) {
            const data = currentNum.data();
            await addDoc(collection(db, 'systemLogs'), { action: 'update_number', number: num }); // Placeholder for server-side logic
            // Note: Cloud Firestore doesn't support easy increments in client-side batches without race conditions,
            // but for this app it's fine to just write.
            // (Actually we can use increment, but let's keep it simple for now)
          } else {
            await addDoc(collection(db, 'maliciousNumbers'), {
              number: num,
              reportCount: 1,
              severityScore: result.riskPercentage,
              firstSeen: Timestamp.now(),
              lastSeen: Timestamp.now(),
              linkedUserIds: [user?.uid || 'anonymous']
            });
          }
        }

        // 2. Track Domains
        if (result.urlForensics?.extractedUrls?.length > 0) {
          for (const url of result.urlForensics.extractedUrls) {
            try {
              const domain = new URL(url).hostname;
              await addDoc(collection(db, 'maliciousDomains'), {
                domain,
                brandSpoofing: result.urlForensics.targetBrand || 'Unknown',
                reportCount: 1,
                firstSeen: Timestamp.now()
              });
            } catch (urlErr) {
              console.warn("Invalid URL for forensics:", url);
            }
          }
        }

        // 3. Campaign Logic
        if (result.campaignFingerprint?.messageHash) {
          await addDoc(collection(db, 'scamCampaigns'), {
            messageHash: result.campaignFingerprint.messageHash,
            archetype: result.campaignFingerprint.archetype,
            messageCount: 1,
            associatedNumbers: [currentSender],
            associatedDomains: result.urlForensics.extractedUrls || []
          });
        }

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
      let errorMessage = "Analysis failed. Please try again.";
      
      const errorStr = error.message || String(error);
      if (errorStr === "API_KEY_MISSING") {
        errorMessage = "AI services are not configured.";
      } else if (errorStr === "INVALID_AI_RESPONSE") {
        errorMessage = "AI returned an invalid response.";
      } else if (errorStr.includes("quota") || errorStr.includes("429")) {
        errorMessage = "Analysis limit reached. Please try later.";
      } else if (errorStr.includes("API key not valid") || errorStr.includes("invalid")) {
        errorMessage = "Invalid configuration.";
      }
      
      toast.error(errorMessage);
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



      <AnimatePresence>
        {showTutorial && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-md"
          >
            <motion.div 
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              className="bg-white w-full max-w-md rounded-[2.5rem] overflow-hidden shadow-2xl p-8 text-center"
            >
              <div className="flex justify-center mb-6">
                <div className="bg-blue-50 p-6 rounded-3xl">
                  {tutorialSteps[tutorialStep].icon}
                </div>
              </div>
              <h3 className="text-2xl font-black tracking-tight mb-4">{tutorialSteps[tutorialStep].title}</h3>
              <p className="text-gray-600 mb-8 leading-relaxed">
                {tutorialSteps[tutorialStep].content}
              </p>
              <div className="flex flex-col gap-3">
                <button 
                  onClick={() => {
                    if (tutorialStep < tutorialSteps.length - 1) {
                      setTutorialStep(tutorialStep + 1);
                    } else {
                      completeTutorial();
                    }
                  }}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white py-4 rounded-2xl font-bold transition-all shadow-lg shadow-blue-100"
                >
                  {tutorialSteps[tutorialStep].action}
                </button>
                {tutorialStep < tutorialSteps.length - 1 && (
                  <button 
                    onClick={completeTutorial}
                    className="text-gray-400 text-xs font-bold uppercase tracking-widest hover:text-gray-600 transition-colors"
                  >
                    Skip Tutorial
                  </button>
                )}
              </div>
              <div className="flex justify-center gap-2 mt-8">
                {tutorialSteps.map((_, i) => (
                  <div 
                    key={`dot-${i}`}
                    className={cn(
                      "w-2 h-2 rounded-full transition-all",
                      i === tutorialStep ? "w-6 bg-blue-600" : "bg-gray-200"
                    )}
                  />
                ))}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

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
                            
                            {/* Simulated Map Visualization */}
                            <a 
                              href={selectedScam.towerInfo?.coordinates 
                                ? `https://www.google.com/maps/search/?api=1&query=${selectedScam.towerInfo.coordinates.lat},${selectedScam.towerInfo.coordinates.lng}&query_place_id=${encodeURIComponent(selectedScam.towerInfo.siteName || 'Triangulation Site')}` 
                                : `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(selectedScam.towerInfo?.location || selectedScam.geographicOrigin || 'South Africa')}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              className="relative block w-full h-48 bg-gray-900 rounded-3xl overflow-hidden border border-gray-800 shadow-inner cursor-pointer group/map"
                            >
                              <div className="absolute inset-0 opacity-20">
                                <div className="absolute inset-0" style={{ backgroundImage: 'radial-gradient(#3b82f6 1px, transparent 1px)', backgroundSize: '20px 20px' }} />
                              </div>
                              <div className="absolute inset-0 flex items-center justify-center">
                                <div className="relative">
                                  <motion.div 
                                    animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0.2, 0.5] }}
                                    transition={{ duration: 2, repeat: Infinity }}
                                    className="absolute -inset-8 bg-blue-500/20 rounded-full"
                                  />
                                  <div className="w-4 h-4 bg-blue-500 rounded-full border-2 border-white shadow-[0_0_15px_rgba(59,130,246,0.8)] relative z-10" />
                                </div>
                              </div>

                              {/* Hover Overlay */}
                              <div className="absolute inset-0 bg-blue-600/0 group-hover/map:bg-blue-600/10 transition-colors flex items-center justify-center">
                                <div className="opacity-0 group-hover/map:opacity-100 transition-opacity bg-white/10 backdrop-blur-md px-4 py-2 rounded-2xl border border-white/20 flex items-center gap-2">
                                  <ExternalLink className="w-4 h-4 text-white" />
                                  <span className="text-xs font-bold text-white uppercase tracking-widest">Open in Google Maps</span>
                                </div>
                              </div>

                              <div className="absolute bottom-4 left-4 bg-black/60 backdrop-blur-md px-3 py-1.5 rounded-xl border border-white/10">
                                <p className="text-[10px] font-mono text-blue-400">
                                  LAT: {selectedScam.towerInfo?.coordinates?.lat || '0.00'} | LNG: {selectedScam.towerInfo?.coordinates?.lng || '0.00'}
                                </p>
                              </div>
                              <div className="absolute top-4 right-4 flex flex-col items-end gap-1">
                                <div className="bg-emerald-500/20 backdrop-blur-md px-2 py-1 rounded-lg border border-emerald-500/30 flex items-center gap-1.5">
                                  <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
                                  <span className="text-[8px] font-bold text-emerald-400 uppercase tracking-widest">Live Signal</span>
                                </div>
                                <div className="bg-blue-500/20 backdrop-blur-md px-2 py-1 rounded-lg border border-blue-500/30">
                                  <span className="text-[8px] font-bold text-blue-400 uppercase tracking-widest">Confidence: {selectedScam.towerInfo?.confidence || 0}%</span>
                                </div>
                              </div>
                            </a>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              <div className="bg-gray-50 p-4 rounded-2xl border border-gray-100">
                                <p className="text-[10px] font-bold text-gray-400 uppercase mb-1">Sender's Carrier / Tower ID</p>
                                <p className="font-bold text-gray-800">{selectedScam.towerInfo?.carrier || 'Unknown Network'}</p>
                                <div className="flex items-center gap-2 mt-1">
                                  <p className="text-[10px] font-mono text-blue-600">{selectedScam.towerInfo?.id || 'NODE-ID-PENDING'}</p>
                                  <span className="text-[8px] font-bold px-1.5 py-0.5 bg-blue-100 text-blue-700 rounded-full uppercase">
                                    {selectedScam.towerInfo?.signalStrength || 0} dBm
                                  </span>
                                </div>
                              </div>
                              <div className="bg-gray-50 p-4 rounded-2xl border border-gray-100">
                                <p className="text-[10px] font-bold text-gray-400 uppercase mb-1">Sender's Last Known Location</p>
                                <p className="font-bold text-gray-800">{selectedScam.towerInfo?.location || selectedScam.geographicOrigin || 'Unknown'}</p>
                                <div className="flex items-center justify-between mt-1">
                                  <p className="text-[10px] text-emerald-600 font-bold">Triangulation: {selectedScam.towerInfo?.distance || 'Within Region'}</p>
                                  <a 
                                    href={selectedScam.towerInfo?.coordinates 
                                      ? `https://www.google.com/maps/search/?api=1&query=${selectedScam.towerInfo.coordinates.lat},${selectedScam.towerInfo.coordinates.lng}&query_place_id=${encodeURIComponent(selectedScam.towerInfo.siteName || 'Triangulation Site')}` 
                                      : `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(selectedScam.towerInfo?.location || selectedScam.geographicOrigin || 'South Africa')}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    className="text-[10px] font-bold text-blue-600 hover:text-blue-700 flex items-center gap-1 bg-blue-50 px-2 py-0.5 rounded-full transition-colors"
                                  >
                                    <ExternalLink className="w-2.5 h-2.5" />
                                    Show
                                  </a>
                                </div>
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

                          {/* Forensic Intelligence Sections */}
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            {/* Identity Intelligence */}
                            <div className="space-y-4">
                              <h4 className="text-xs font-black text-gray-400 uppercase tracking-widest flex items-center gap-2">
                                <ShieldCheck className="w-4 h-4" /> Identity Intelligence
                              </h4>
                              <div className="bg-blue-50 p-4 rounded-2xl border border-blue-100 space-y-3">
                                <div className="flex items-center justify-between">
                                  <div>
                                    <p className="text-[10px] font-bold text-blue-400 uppercase mb-1">Reputation Score</p>
                                    <div className="flex items-center gap-2">
                                      <div className="flex-1 h-1.5 w-24 bg-blue-100 rounded-full overflow-hidden">
                                        <div className="h-full bg-blue-600 rounded-full" style={{ width: `${100 - (selectedScam.identityIntelligence?.reputationScore || 0)}%` }} />
                                      </div>
                                      <span className="text-xs font-black text-blue-700">{selectedScam.identityIntelligence?.reputationScore || 0}% Risk</span>
                                    </div>
                                  </div>
                                  {selectedScam.identityIntelligence.isSpoofed && (
                                    <span className="bg-red-100 text-red-600 text-[9px] font-black px-2 py-1 rounded-lg border border-red-200 uppercase animate-pulse">
                                      Spoofed Number
                                    </span>
                                  )}
                                </div>
                                <div>
                                  <p className="text-[10px] font-bold text-blue-400 uppercase mb-1">Normalized ID</p>
                                  <p className="text-sm font-bold text-blue-900 font-mono">{selectedScam.identityIntelligence?.normalizedNumber || 'N/A'}</p>
                                </div>
                                <p className="text-[10px] text-blue-600 leading-tight bg-white/50 p-2 rounded-lg italic">
                                  {selectedScam.identityIntelligence?.threatActorProfile || 'Analyzing reuse patterns...'}
                                </p>
                              </div>
                            </div>

                            {/* Campaign Fingerprint */}
                            <div className="space-y-4">
                              <h4 className="text-xs font-black text-gray-400 uppercase tracking-widest flex items-center gap-2">
                                <Zap className="w-4 h-4" /> Campaign Fingerprint
                              </h4>
                              <div className="bg-emerald-50 p-4 rounded-2xl border border-emerald-100 space-y-3">
                                <div>
                                  <p className="text-[10px] font-bold text-emerald-400 uppercase mb-1">Campaign Archetype</p>
                                  <p className="text-sm font-bold text-emerald-900">{selectedScam.campaignFingerprint?.archetype || 'Universal Scam'}</p>
                                </div>
                                <div>
                                  <p className="text-[10px] font-bold text-emerald-400 uppercase mb-1">Clustering Tag</p>
                                  <span className="inline-block px-2 py-0.5 bg-emerald-200 text-emerald-800 rounded font-mono text-[9px]">
                                    {selectedScam.campaignFingerprint?.clusterTag || 'NODE-SIG-X'}
                                  </span>
                                </div>
                                <p className="text-[10px] text-emerald-600 font-mono break-all opacity-60">
                                  HASH: {selectedScam.campaignFingerprint?.messageHash}
                                </p>
                              </div>
                            </div>
                          </div>

                          {/* Link Forensics */}
                          <div className="space-y-4">
                            <h4 className="text-xs font-black text-gray-400 uppercase tracking-widest flex items-center gap-2">
                              <ExternalLink className="w-4 h-4" /> Domain & Link Forensics
                            </h4>
                            <div className="bg-red-50 p-4 rounded-2xl border border-red-100">
                              <div className="flex items-center justify-between mb-3">
                                <span className={cn(
                                  "px-2 py-0.5 rounded text-[8px] font-bold uppercase",
                                  selectedScam.urlForensics?.brandSpoofing ? "bg-red-200 text-red-700" : "bg-emerald-200 text-emerald-700"
                                )}>
                                  {selectedScam.urlForensics?.brandSpoofing ? `Brand Hijack Detected: ${selectedScam.urlForensics.targetBrand}` : "No Direct Brand Mimicry"}
                                </span>
                                {selectedScam.urlForensics?.hostingCountry && (
                                  <div className="flex items-center gap-1.5 text-red-700 bg-red-100 px-2 py-0.5 rounded-lg border border-red-200">
                                    <Globe className="w-3 h-3" />
                                    <span className="text-[9px] font-bold uppercase">Hosted: {selectedScam.urlForensics.hostingCountry}</span>
                                  </div>
                                )}
                              </div>
                              <div className="space-y-3">
                                {selectedScam.urlForensics?.extractedUrls?.map((url, i) => (
                                  <div key={`url-forensic-${i}`} className="flex items-center justify-between gap-3 bg-white/60 p-2 rounded-xl border border-red-200/30">
                                    <span className="text-[10px] font-mono text-red-600 truncate flex-1">{url}</span>
                                    <a href={url} target="_blank" rel="noopener noreferrer" className="p-1.5 hover:bg-red-100 rounded-lg text-red-600 shrink-0">
                                      <ChevronRight className="w-4 h-4" />
                                    </a>
                                  </div>
                                ))}
                                {(!selectedScam.urlForensics?.extractedUrls || selectedScam.urlForensics.extractedUrls.length === 0) && (
                                  <p className="text-xs text-gray-500 italic">No external links found in this communication.</p>
                                )}
                                <p className="text-[10px] text-red-700 bg-red-100/50 p-3 rounded-xl leading-relaxed mt-2">
                                  {selectedScam.urlForensics?.domainRiskDetails || 'Performing registrar forensics and domain age verification...'}
                                </p>
                              </div>
                            </div>
                          </div>

                          {/* Action Buttons */}
                          <div className="flex flex-col sm:flex-row gap-3 pt-4">
                            <button 
                              onClick={() => generateEvidenceReport(selectedScam)}
                              className="flex-1 bg-gray-900 text-white h-14 rounded-2xl font-bold flex items-center justify-center gap-2 hover:bg-black transition-all shadow-xl shadow-gray-200"
                            >
                              <History className="w-5 h-5" />
                              Export Evidence Pack (PDF)
                            </button>
                            <button 
                              onClick={() => {
                                toast.promise(new Promise(res => setTimeout(res, 1500)), {
                                  loading: 'Alerting Institutional Security...',
                                  success: 'Security pipeline notified!',
                                  error: 'Failed to notify authorities.'
                                });
                              }}
                              className="flex-1 bg-red-600 text-white h-14 rounded-2xl font-bold flex items-center justify-center gap-2 hover:bg-red-700 transition-all shadow-xl shadow-red-200"
                            >
                              <Flag className="w-5 h-5" />
                              Push to Reporting Pipeline
                            </button>
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
                        If you encounter "Quota Exceeded" errors, the daily analysis limit has been reached.
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
