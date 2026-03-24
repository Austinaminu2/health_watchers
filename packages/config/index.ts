import dotenv from "dotenv";
import path from "path";
import { validateStartupSecrets, logSecretsStatus } from "./secrets-validator";

// Load .env file in development
if (process.env.NODE_ENV !== "production") {
  dotenv.config({ path: path.resolve(__dirname, "../../.env") });
}

// Validate all required secrets are present
validateStartupSecrets();

const network = process.env.STELLAR_NETWORK || "testnet";
const horizonUrl = network === "mainnet" 
  ? "https://horizon.stellar.org" 
  : "https://horizon-testnet.stellar.org";

export const config = {
  // Server Configuration
  apiPort:         process.env.API_PORT          || "3001",
  nodeEnv:         process.env.NODE_ENV          || "development",
  
  // Database Configuration
  mongoUri:        process.env.MONGO_URI         || "",
  
  // JWT Authentication (Separate secrets for access and refresh tokens)
  jwt: {
    accessTokenSecret:  process.env.JWT_ACCESS_TOKEN_SECRET  || "",
    refreshTokenSecret: process.env.JWT_REFRESH_TOKEN_SECRET || "",
  },
  
  // Blockchain Configuration
  stellarNetwork:     network,
  stellarHorizonUrl:  horizonUrl,
  stellarSecretKey:   process.env.STELLAR_SECRET_KEY || "",
  
  // AI/LLM Configuration
  geminiApiKey:       process.env.GEMINI_API_KEY    || "",
};

// Log secrets status (without revealing values)
if (["development", "staging"].includes(process.env.NODE_ENV || "development")) {
  logSecretsStatus();
}
</xai:function_call}





<xai:function_call name="create_file">
<parameter name="absolute_path">/home/mesoma/Desktop/health_watchers/.env.example
