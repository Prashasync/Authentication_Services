const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");

const client = new SecretsManagerClient({ region: "us-east-1" });
const secret_name = "REACT_APP_SERVER"; 

async function loadSecrets() {
  try {
    const command = new GetSecretValueCommand({ 
      SecretId: secret_name,
      VersionStage: "AWSCURRENT",
    });

    const response = await client.send(command);
    const secretString = response.SecretString;
    const secrets = JSON.parse(secretString);

    // Inject into process.env
    for (const key in secrets) {
      process.env[key] = secrets[key];
    }

    console.log("✅ SECRETS LOADED IN ENV");
  } catch (error) {
    console.error("❌ Failed to load secrets from AWS:", error);
    throw error;
  }
}

module.exports = { loadSecrets };
