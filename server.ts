import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import dotenv from "dotenv";
import { GoogleGenAI, Type } from "@google/genai";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// --- AI Setup ---
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

const getAI = () => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error("GEMINI_API_KEY is not set in environment variables");
  }
  return new GoogleGenAI({ apiKey });
};

app.post("/api/scan", async (req, res) => {
  try {
    const { messageContent, senderNumber, inputSource } = req.body;
    
    const ai = getAI();
    const response = await ai.models.generateContent({
      model: "gemini-1.5-flash",
      contents: `Analyze this communication for registration scams. 
      INPUT METHOD: ${(inputSource || 'unknown').toUpperCase()}
      SENDER NUMBER: ${senderNumber || 'Unknown'}
      MESSAGE CONTENT: "${messageContent || 'No message content provided - trace by number only'}"
      
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
    res.json(JSON.parse(cleanedJson));
  } catch (error: any) {
    console.error("AI Scan Error:", error);
    res.status(500).json({ error: error.message || "Internal server error" });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ 
    status: "ok", 
    env: process.env.NODE_ENV,
    hasKey: !!process.env.GEMINI_API_KEY
  });
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // Only listen if not in a serverless environment (like Vercel)
  if (process.env.NODE_ENV !== "production" || !process.env.VERCEL) {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  }
}

startServer();

// Export for Vercel
export default app;
