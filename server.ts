import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import dotenv from "dotenv";
import { GoogleGenerativeAI, SchemaType } from "@google/generative-ai";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

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
    throw new Error("API_KEY_MISSING");
  }
  return new GoogleGenerativeAI(apiKey);
};

app.post("/api/scan", async (req, res) => {
  try {
    const { messageContent, senderNumber, inputSource } = req.body;
    
    if (!messageContent && !senderNumber) {
      return res.status(400).json({ error: "Missing content or sender number" });
    }

    const genAI = getAI();
    // Use gemini-1.5-flash which is widely available
    const model = genAI.getGenerativeModel({ 
      model: "gemini-1.5-flash",
      systemInstruction: SYSTEM_PROMPT,
    });

    const result = await model.generateContent({
      contents: [{
        role: "user",
        parts: [{
          text: `Analyze this communication for registration scams. 
          INPUT METHOD: ${(inputSource || 'unknown').toUpperCase()}
          SENDER NUMBER: ${senderNumber || 'Unknown'}
          MESSAGE CONTENT: "${messageContent || 'No message content provided - trace by number only'}"
          
          If no message content is provided, focus your analysis on the sender number's reputation, geographic origin, and likely network carrier.`
        }]
      }],
      generationConfig: {
        responseMimeType: "application/json",
        responseSchema: {
          type: SchemaType.OBJECT,
          properties: {
            riskPercentage: { type: SchemaType.NUMBER },
            reason: { type: SchemaType.STRING },
            inputSource: { type: SchemaType.STRING },
            geographicOrigin: { type: SchemaType.STRING },
            identityIntelligence: {
              type: SchemaType.OBJECT,
              properties: {
                normalizedNumber: { type: SchemaType.STRING },
                reputationScore: { type: SchemaType.NUMBER },
                threatActorProfile: { type: SchemaType.STRING },
                isSpoofed: { type: SchemaType.BOOLEAN }
              },
              required: ["normalizedNumber", "reputationScore", "isSpoofed"]
            },
            urlForensics: {
              type: SchemaType.OBJECT,
              properties: {
                extractedUrls: { type: SchemaType.ARRAY, items: { type: SchemaType.STRING } },
                brandSpoofing: { type: SchemaType.BOOLEAN },
                targetBrand: { type: SchemaType.STRING },
                domainRiskDetails: { type: SchemaType.STRING },
                hostingCountry: { type: SchemaType.STRING }
              },
              required: ["extractedUrls", "brandSpoofing", "domainRiskDetails", "hostingCountry"]
            },
            campaignFingerprint: {
              type: SchemaType.OBJECT,
              properties: {
                messageHash: { type: SchemaType.STRING },
                archetype: { type: SchemaType.STRING },
                clusterTag: { type: SchemaType.STRING }
              },
              required: ["messageHash", "archetype", "clusterTag"]
            },
            towerInfo: {
              type: SchemaType.OBJECT,
              properties: {
                id: { type: SchemaType.STRING },
                location: { type: SchemaType.STRING },
                siteName: { type: SchemaType.STRING },
                carrier: { type: SchemaType.STRING },
                distance: { type: SchemaType.STRING },
                signalStrength: { type: SchemaType.NUMBER },
                confidence: { type: SchemaType.NUMBER },
                coordinates: {
                  type: SchemaType.OBJECT,
                  properties: {
                    lat: { type: SchemaType.NUMBER },
                    lng: { type: SchemaType.NUMBER }
                  },
                  required: ["lat", "lng"]
                }
              },
              required: ["id", "location", "siteName", "carrier", "distance", "signalStrength", "confidence", "coordinates"]
            },
            layersResults: {
              type: SchemaType.OBJECT,
              properties: {
                urgency: { 
                  type: SchemaType.OBJECT, 
                  properties: { score: { type: SchemaType.NUMBER }, details: { type: SchemaType.STRING } },
                  required: ["score", "details"]
                },
                financial: { 
                  type: SchemaType.OBJECT, 
                  properties: { score: { type: SchemaType.NUMBER }, details: { type: SchemaType.STRING } },
                  required: ["score", "details"]
                },
                url: { 
                  type: SchemaType.OBJECT, 
                  properties: { score: { type: SchemaType.NUMBER }, details: { type: SchemaType.STRING } },
                  required: ["score", "details"]
                },
                impersonation: { 
                  type: SchemaType.OBJECT, 
                  properties: { score: { type: SchemaType.NUMBER }, details: { type: SchemaType.STRING } },
                  required: ["score", "details"]
                },
                linguistic: { 
                  type: SchemaType.OBJECT, 
                  properties: { score: { type: SchemaType.NUMBER }, details: { type: SchemaType.STRING } },
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

    const response = await result.response;
    const jsonText = response.text();
    const cleanedJson = jsonText.replace(/```json\n?|```/g, '').trim();
    res.json(JSON.parse(cleanedJson));
  } catch (error: any) {
    console.error("AI Scan Error:", error);
    // Explicitly handle API key errors to send back a string that the frontend can recognize
    const errorMessage = error.message || String(error);
    if (errorMessage.includes("API_KEY_INVALID") || errorMessage.includes("API key not valid")) {
       return res.status(401).json({ error: "INVALID_CONFIGURATION" });
    }
    res.status(500).json({ error: errorMessage });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ 
    status: "ok", 
    env: process.env.NODE_ENV
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
