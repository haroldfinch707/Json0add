const DETECTOR_INTELLIGENCE = {
  // Cloud Providers
  "AWS": {
    service: "Amazon Web Services",
    category: "Cloud Provider",
    impact: "Complete AWS account access, resource manipulation, billing fraud, data exfiltration from S3/RDS/EC2",
    severity: "Critical",
    poc_template: "1. Locate exposed AWS credentials\n2. Configure AWS CLI with found credentials\n3. Run 'aws sts get-caller-identity' to verify access\n4. Enumerate accessible resources with 'aws s3 ls' or 'aws ec2 describe-instances'",
    remediation: "Immediately rotate credentials in AWS IAM Console and review CloudTrail logs for unauthorized access"
  },
  
  "AzureStorage": {
    service: "Microsoft Azure Storage",
    category: "Cloud Storage",
    impact: "Access to Azure storage accounts, blob manipulation, data exfiltration, storage cost manipulation",
    severity: "High",
    poc_template: "1. Extract Azure storage connection string\n2. Use Azure Storage Explorer or CLI to connect\n3. List containers and blobs\n4. Download sensitive data as proof",
    remediation: "Regenerate storage account keys in Azure Portal immediately"
  },

  "GoogleCloudStorage": {
    service: "Google Cloud Storage",
    category: "Cloud Storage", 
    impact: "GCS bucket access, data exfiltration, billing manipulation, unauthorized file uploads",
    severity: "High",
    poc_template: "1. Configure gcloud with exposed credentials\n2. Run 'gsutil ls' to list accessible buckets\n3. Download sample files as proof\n4. Check bucket permissions",
    remediation: "Revoke service account key in Google Cloud Console and audit bucket access logs"
  },

  // API Services
  "Infura": {
    service: "Infura Ethereum API",
    category: "Blockchain Infrastructure",
    impact: "Ethereum network access abuse, transaction monitoring, rate limit exhaustion, potential smart contract manipulation",
    severity: "Medium",
    poc_template: "1. Use exposed Infura API key in web3 requests\n2. Make RPC calls to mainnet/testnet endpoints\n3. Monitor transaction data and block information\n4. Demonstrate rate limit consumption",
    remediation: "Revoke API key in Infura dashboard and monitor usage statistics for anomalies"
  },

  "Stripe": {
    service: "Stripe Payment Processing",
    category: "Payment Gateway",
    impact: "Payment manipulation, customer data access, webhook tampering, financial fraud, PCI compliance violation",
    severity: "Critical",
    poc_template: "1. Use exposed Stripe API key to list customers\n2. Retrieve payment methods and transaction history\n3. Attempt to create test charges\n4. Access webhook endpoints",
    remediation: "Immediately revoke API key in Stripe dashboard, audit all transactions, and notify affected customers"
  },

  "Twilio": {
    service: "Twilio Communications API",
    category: "Communication Service",
    impact: "SMS/voice spam, phone number enumeration, toll fraud, customer communication interception",
    severity: "High",
    poc_template: "1. Authenticate with exposed Twilio credentials\n2. List account phone numbers and message history\n3. Send test SMS to demonstrate access\n4. Check call logs and recording access",
    remediation: "Rotate API credentials in Twilio console and review usage logs for unauthorized activity"
  },

  "SendGrid": {
    service: "SendGrid Email Service",
    category: "Email Service",
    impact: "Email spam campaigns, customer data access, reputation damage, phishing attacks from legitimate domain",
    severity: "High",
    poc_template: "1. Use API key to access SendGrid account\n2. List email templates and contact lists\n3. Send test email to demonstrate access\n4. Check sending statistics and reputation",
    remediation: "Revoke API key immediately and monitor email reputation and delivery statistics"
  },

  "Slack": {
    service: "Slack Workspace",
    category: "Communication Platform",
    impact: "Internal communication access, sensitive data exfiltration, user impersonation, file downloads",
    severity: "High",
    poc_template: "1. Use bot token to access Slack API\n2. List channels and read message history\n3. Download shared files\n4. Access user profiles and contact information",
    remediation: "Revoke bot token in Slack app settings and audit channel access logs"
  },

  // Database Services
  "MongoDB": {
    service: "MongoDB Database",
    category: "Database",
    impact: "Complete database access, data exfiltration, data manipulation, ransomware attacks, customer PII exposure",
    severity: "Critical",
    poc_template: "1. Connect to MongoDB using exposed connection string\n2. List databases and collections\n3. Query sensitive data (limit to sample)\n4. Demonstrate write access with test document",
    remediation: "Change database password immediately, enable authentication, and audit recent connections"
  },

  "PostgreSQL": {
    service: "PostgreSQL Database",
    category: "Database",
    impact: "Database access, SQL injection potential, data exfiltration, data corruption, privilege escalation",
    severity: "Critical",
    poc_template: "1. Connect using exposed PostgreSQL credentials\n2. List databases and tables\n3. Query sample data from sensitive tables\n4. Check user privileges and permissions",
    remediation: "Change database password, review user permissions, and enable connection logging"
  },

  "Redis": {
    service: "Redis Cache Database",
    category: "Cache/Database",
    impact: "Cache data access, session hijacking, data manipulation, potential code execution via Lua scripts",
    severity: "High",
    poc_template: "1. Connect to Redis instance with exposed credentials\n2. Run 'KEYS *' to list cached data\n3. Retrieve sample session data or cached information\n4. Test write permissions with SET command",
    remediation: "Change Redis password, enable authentication, and review cached sensitive data"
  },

  // Social Media & Marketing
  "Facebook": {
    service: "Facebook Graph API",
    category: "Social Media",
    impact: "Facebook page/app access, user data harvesting, unauthorized posting, ad account manipulation",
    severity: "Medium",
    poc_template: "1. Use access token with Facebook Graph API\n2. Retrieve user/page information\n3. Check permissions and accessible data\n4. Attempt to post content (if write permissions exist)",
    remediation: "Revoke access token in Facebook Developer Console and audit app permissions"
  },

  "Twitter": {
    service: "Twitter API",
    category: "Social Media",
    impact: "Account takeover, unauthorized tweets, DM access, follower manipulation, reputation damage",
    severity: "Medium",
    poc_template: "1. Authenticate with Twitter API using exposed keys\n2. Retrieve account information and tweet history\n3. Check DM access permissions\n4. Demonstrate posting capability (use test message)",
    remediation: "Regenerate API keys in Twitter Developer Portal and review recent account activity"
  },

  "Mailchimp": {
    service: "Mailchimp Email Marketing",
    category: "Email Marketing",
    impact: "Email list access, subscriber data exfiltration, unauthorized email campaigns, reputation damage",
    severity: "Medium",
    poc_template: "1. Access Mailchimp account using API key\n2. List email campaigns and subscriber data\n3. Download sample subscriber information\n4. Check campaign statistics and templates",
    remediation: "Generate new API key in Mailchimp and audit recent campaign activity"
  },

  // Development & CI/CD
  "GitHub": {
    service: "GitHub Repository Access",
    category: "Version Control",
    impact: "Source code access, private repository cloning, commit history access, organizational data exposure",
    severity: "High",
    poc_template: "1. Use personal access token to access GitHub API\n2. List accessible repositories and organizations\n3. Clone private repository as proof\n4. Check collaborator and team access",
    remediation: "Revoke personal access token in GitHub settings and audit repository access logs"
  },

  "GitLab": {
    service: "GitLab Repository Access",
    category: "Version Control",
    impact: "Project access, CI/CD pipeline manipulation, merge request access, deployment key compromise",
    severity: "High",
    poc_template: "1. Authenticate with GitLab using access token\n2. List accessible projects and groups\n3. Download project files as proof\n4. Check CI/CD variables and pipeline access",
    remediation: "Revoke access token in GitLab user settings and review project access logs"
  },

  "Docker": {
    service: "Docker Registry",
    category: "Container Registry",
    impact: "Container image access, proprietary code exposure, malicious image uploads, supply chain attacks",
    severity: "Medium",
    poc_template: "1. Login to Docker registry with exposed credentials\n2. Pull private container images\n3. Inspect image layers for sensitive data\n4. Check push permissions to registry",
    remediation: "Change Docker registry password and audit recent image pulls/pushes"
  },

  "NPM": {
    service: "NPM Package Registry",
    category: "Package Registry",
    impact: "Package publishing abuse, supply chain attacks, private package access, malicious code injection",
    severity: "High",
    poc_template: "1. Login to NPM with exposed token\n2. List accessible packages and organizations\n3. Download private packages as proof\n4. Check publishing permissions",
    remediation: "Revoke NPM token and audit recent package activity and downloads"
  },

  // CI/CD & DevOps
  "Jenkins": {
    service: "Jenkins CI/CD",
    category: "CI/CD Platform",
    impact: "Build pipeline access, deployment manipulation, environment variable exposure, code injection",
    severity: "High",
    poc_template: "1. Access Jenkins with exposed credentials\n2. View build history and job configurations\n3. Check environment variables and secrets\n4. Demonstrate job execution capability",
    remediation: "Change Jenkins password, enable 2FA, and audit recent build activities"
  },

  "CircleCI": {
    service: "CircleCI Build Platform",
    category: "CI/CD Platform",
    impact: "Build access, environment variable exposure, deployment key access, artifact manipulation",
    severity: "Medium",
    poc_template: "1. Use API token to access CircleCI projects\n2. View build logs and environment variables\n3. Download build artifacts\n4. Check workflow configurations",
    remediation: "Revoke API token in CircleCI settings and audit environment variables"
  },

  // Analytics & Monitoring
  "GoogleAnalytics": {
    service: "Google Analytics",
    category: "Analytics Platform",
    impact: "Website traffic data access, user behavior analysis, conversion tracking exposure, audience data",
    severity: "Low",
    poc_template: "1. Use service account to access Analytics API\n2. Retrieve website traffic data\n3. Export user behavior and conversion data\n4. Check accessible properties and views",
    remediation: "Revoke service account access in Google Analytics and review data sharing settings"
  },

  "Mixpanel": {
    service: "Mixpanel Analytics",
    category: "Analytics Platform",
    impact: "User behavior data access, event tracking exposure, funnel analysis, user property data",
    severity: "Low",
    poc_template: "1. Access Mixpanel using API credentials\n2. Export user event data and properties\n3. View funnel and cohort analysis\n4. Check data export capabilities",
    remediation: "Reset API credentials in Mixpanel project settings"
  },

  // Payment & Financial
  "PayPal": {
    service: "PayPal Payment API",
    category: "Payment Gateway",
    impact: "Payment processing access, transaction history, customer financial data, refund manipulation",
    severity: "Critical",
    poc_template: "1. Authenticate with PayPal API credentials\n2. List recent transactions and customer data\n3. Check refund and payment capabilities\n4. Access webhook configurations",
    remediation: "Immediately revoke API credentials in PayPal developer console and audit transactions"
  },

  "Square": {
    service: "Square Payment Processing",
    category: "Payment Gateway",
    impact: "Payment terminal access, transaction data, customer information, inventory management",
    severity: "High",
    poc_template: "1. Use Square API token to access account\n2. Retrieve transaction history and customer data\n3. Check payment and refund capabilities\n4. Access location and device information",
    remediation: "Revoke access token in Square Developer Dashboard and review recent transactions"
  },

  // Communication & SMS
  "Nexmo": {
    service: "Vonage/Nexmo Communication API",
    category: "Communication Service",
    impact: "SMS/voice abuse, phone number verification bypass, toll fraud, customer communication access",
    severity: "Medium",
    poc_template: "1. Authenticate with Nexmo API credentials\n2. Send test SMS to verify access\n3. Check voice calling capabilities\n4. Review number verification services",
    remediation: "Reset API credentials in Vonage dashboard and monitor usage for anomalies"
  },

  "MessageBird": {
    service: "MessageBird Communication Platform",
    category: "Communication Service",
    impact: "SMS/voice spam, conversation access, contact list exposure, toll fraud",
    severity: "Medium",
    poc_template: "1. Use API key to access MessageBird services\n2. Send test message to demonstrate access\n3. List conversation history and contacts\n4. Check voice calling permissions",
    remediation: "Generate new API key and audit recent communication activity"
  },

  // Domain & DNS
  "Cloudflare": {
    service: "Cloudflare DNS & CDN",
    category: "CDN/DNS Provider",
    impact: "DNS manipulation, domain hijacking, SSL certificate access, traffic routing abuse",
    severity: "High",
    poc_template: "1. Use API token to access Cloudflare account\n2. List managed domains and DNS records\n3. Check SSL certificate access\n4. Review firewall and security settings",
    remediation: "Revoke API token in Cloudflare dashboard and audit recent DNS changes"
  },

  "DigitalOcean": {
    service: "DigitalOcean Cloud Platform",
    category: "Cloud Provider",
    impact: "Droplet access, database manipulation, storage access, billing fraud, resource abuse",
    severity: "High",
    poc_template: "1. Authenticate with DigitalOcean API token\n2. List droplets, databases, and storage\n3. Check SSH key access and firewall rules\n4. Review billing and usage information",
    remediation: "Regenerate API token and audit recent resource changes and billing activity"
  },

  // Default template for unknown detectors
  "Unknown": {
    service: "Unknown Service",
    category: "Unknown",
    impact: "Potential unauthorized access to external services, data exposure, or account compromise",
    severity: "Medium",
    poc_template: "1. Identify the service associated with the exposed secret\n2. Test authentication using the found credentials\n3. Document accessible resources and data\n4. Assess potential impact based on service capabilities",
    remediation: "Identify the service, revoke/rotate the exposed credentials, and audit recent access logs"
  }
};

// Helper function to get detector intelligence
function getDetectorIntelligence(detectorName) {
  return DETECTOR_INTELLIGENCE[detectorName] || DETECTOR_INTELLIGENCE["Unknown"];
}

// Function to generate report sections
function generateBugBountyReport(secretData) {
  const detector = secretData.detector || "Unknown";
  const intelligence = getDetectorIntelligence(detector);
  const repoName = extractRepoName(secretData.repo_url);
  const fileName = extractFileName(secretData.file_path);
  
  // Generate complete commit URL
  let commitUrl = '';
  if (secretData.commit_url) {
    commitUrl = secretData.commit_url;
  } else if (secretData.repo_url && secretData.commit) {
    commitUrl = `${secretData.repo_url}/commit/${secretData.commit}`;
  } else {
    commitUrl = 'N/A';
  }
  
  return {
    title: `Exposed ${intelligence.service} Credentials in ${repoName} - GitHub Commit`,
    
    summary: `A ${intelligence.category.toLowerCase()} credential for ${intelligence.service} was found exposed in the public repository "${repoName}". The secret was detected in the file "${fileName}" and ${secretData.verified ? 'has been verified as active' : 'appears to be potentially active'}. This exposure poses a ${intelligence.severity.toLowerCase()} security risk to the organization.`,
    
    poc: `**Proof of Concept:**\n\n${intelligence.poc_template}\n\n**Location Details:**\n- Repository: ${secretData.repo_url}\n- File: ${secretData.file_path}\n- Commit URL: ${commitUrl}`,
    
    impact: `**Business Impact:**\n\n${intelligence.impact}\n\n**Severity:** ${intelligence.severity}\n\n**Potential Consequences:**\n- Unauthorized access to ${intelligence.service}\n- Data breach and privacy violations\n- Financial loss through resource abuse\n- Reputation damage and customer trust loss\n- Compliance violations (GDPR, PCI-DSS, etc.)\n\n**Recommended Actions:**\n${intelligence.remediation}`,
    
    severity: intelligence.severity
  };
}


// Helper functions
function extractRepoName(url) {
  if (!url) return 'Unknown Repository';
  const parts = url.split('/');
  return parts.length >= 2 ? parts[parts.length - 1] : url;
}

function extractFileName(path) {
  if (!path) return 'Unknown File';
  return path.split('/').pop();
}

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { DETECTOR_INTELLIGENCE, getDetectorIntelligence, generateBugBountyReport };
}
