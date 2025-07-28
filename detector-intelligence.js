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

  "DigitalOcean": {
    service: "DigitalOcean Cloud Platform",
    category: "Cloud Provider",
    impact: "Droplet access, database manipulation, storage access, billing fraud, resource abuse",
    severity: "High",
    poc_template: "1. Authenticate with DigitalOcean API token\n2. List droplets, databases, and storage\n3. Check SSH key access and firewall rules\n4. Review billing and usage information",
    remediation: "Regenerate API token and audit recent resource changes and billing activity"
  },

  "Heroku": {
    service: "Heroku Platform",
    category: "Cloud Platform",
    impact: "Application deployment access, environment variable exposure, database access, billing manipulation",
    severity: "High",
    poc_template: "1. Use API key to access Heroku account\n2. List applications and their configurations\n3. Access environment variables and add-ons\n4. Check deployment history and logs",
    remediation: "Regenerate API key in Heroku dashboard and audit recent application changes"
  },

  "Vercel": {
    service: "Vercel Deployment Platform",
    category: "Cloud Platform",
    impact: "Project deployment access, environment variable exposure, domain manipulation, team access",
    severity: "Medium",
    poc_template: "1. Authenticate with Vercel API token\n2. List projects and deployments\n3. Access environment variables and logs\n4. Check team and domain configurations",
    remediation: "Revoke API token in Vercel dashboard and review project access"
  },

  // API Services & Blockchain
  "Infura": {
    service: "Infura Ethereum API",
    category: "Blockchain Infrastructure",
    impact: "Ethereum network access abuse, transaction monitoring, rate limit exhaustion, potential smart contract manipulation",
    severity: "Medium",
    poc_template: "1. Use exposed Infura API key in web3 requests\n2. Make RPC calls to mainnet/testnet endpoints\n3. Monitor transaction data and block information\n4. Demonstrate rate limit consumption",
    remediation: "Revoke API key in Infura dashboard and monitor usage statistics for anomalies"
  },

  "Alchemy": {
    service: "Alchemy Blockchain API",
    category: "Blockchain Infrastructure",
    impact: "Blockchain data access, API rate limit abuse, transaction monitoring, network analysis",
    severity: "Medium",
    poc_template: "1. Use API key to access Alchemy endpoints\n2. Query blockchain data and transaction history\n3. Access NFT and token metadata\n4. Monitor API usage and limits",
    remediation: "Regenerate API key in Alchemy dashboard and monitor usage analytics"
  },

  "Moralis": {
    service: "Moralis Web3 API",
    category: "Blockchain Infrastructure",
    impact: "Web3 data access, DeFi protocol interaction, NFT metadata access, cross-chain data exposure",
    severity: "Medium",
    poc_template: "1. Authenticate with Moralis API key\n2. Access wallet balances and transaction history\n3. Query NFT collections and metadata\n4. Interact with DeFi protocols",
    remediation: "Reset API key in Moralis admin panel and review usage logs"
  },

  // Payment Gateways
  "Stripe": {
    service: "Stripe Payment Processing",
    category: "Payment Gateway",
    impact: "Payment manipulation, customer data access, webhook tampering, financial fraud, PCI compliance violation",
    severity: "Critical",
    poc_template: "1. Use exposed Stripe API key to list customers\n2. Retrieve payment methods and transaction history\n3. Attempt to create test charges\n4. Access webhook endpoints",
    remediation: "Immediately revoke API key in Stripe dashboard, audit all transactions, and notify affected customers"
  },

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

  "Razorpay": {
    service: "Razorpay Payment Gateway",
    category: "Payment Gateway",
    impact: "Payment processing access, customer data exposure, transaction manipulation, refund abuse",
    severity: "Critical",
    poc_template: "1. Use API credentials to access Razorpay dashboard\n2. List payments and customer information\n3. Check refund and settlement capabilities\n4. Access webhook configurations",
    remediation: "Immediately regenerate API keys and audit all recent transactions"
  },

  // Communication Services
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

  "Plivo": {
    service: "Plivo Communication API",
    category: "Communication Service",
    impact: "SMS/voice service abuse, toll fraud, communication interception, account takeover",
    severity: "Medium",
    poc_template: "1. Authenticate with Plivo API credentials\n2. Send test SMS or make voice call\n3. Access call logs and message history\n4. Check account balance and usage",
    remediation: "Reset API credentials and monitor account usage for unauthorized activity"
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

  "MySQL": {
    service: "MySQL Database",
    category: "Database",
    impact: "Database access, data exfiltration, data manipulation, privilege escalation, backup access",
    severity: "Critical",
    poc_template: "1. Connect using exposed MySQL credentials\n2. Show databases and tables\n3. Query sample sensitive data\n4. Check user permissions and grants",
    remediation: "Change database password immediately and audit user access permissions"
  },

  "ElasticSearch": {
    service: "Elasticsearch Database",
    category: "Search Engine/Database",
    impact: "Search index access, data exfiltration, cluster manipulation, performance degradation",
    severity: "High",
    poc_template: "1. Connect to Elasticsearch cluster\n2. List indices and mappings\n3. Query sample documents from sensitive indices\n4. Check cluster health and settings",
    remediation: "Enable authentication, change cluster credentials, and audit recent queries"
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

  "LinkedIn": {
    service: "LinkedIn API",
    category: "Social Media",
    impact: "Profile access, connection data, unauthorized posting, company page manipulation",
    severity: "Medium",
    poc_template: "1. Use OAuth token to access LinkedIn API\n2. Retrieve profile and connection information\n3. Check posting and sharing permissions\n4. Access company page data if available",
    remediation: "Revoke OAuth tokens and audit recent API activity"
  },

  "Instagram": {
    service: "Instagram Basic Display API",
    category: "Social Media",
    impact: "Account access, media downloads, user data exposure, unauthorized posting",
    severity: "Medium",
    poc_template: "1. Use access token to query Instagram API\n2. Retrieve user media and profile information\n3. Check available permissions and scopes\n4. Download sample media content",
    remediation: "Revoke access token in Facebook Developer Console"
  },

  "Mailchimp": {
    service: "Mailchimp Email Marketing",
    category: "Email Marketing",
    impact: "Email list access, subscriber data exfiltration, unauthorized email campaigns, reputation damage",
    severity: "Medium",
    poc_template: "1. Access Mailchimp account using API key\n2. List email campaigns and subscriber data\n3. Download sample subscriber information\n4. Check campaign statistics and templates",
    remediation: "Generate new API key in Mailchimp and audit recent campaign activity"
  },

  // Development & Version Control
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

  "Bitbucket": {
    service: "Bitbucket Repository Access",
    category: "Version Control",
    impact: "Repository access, source code exposure, pipeline manipulation, team data access",
    severity: "High",
    poc_template: "1. Use app password or OAuth token\n2. List accessible repositories and workspaces\n3. Clone private repositories\n4. Check pipeline configurations and variables",
    remediation: "Revoke app passwords and OAuth tokens in Bitbucket settings"
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

  "TravisCI": {
    service: "Travis CI Platform",
    category: "CI/CD Platform",
    impact: "Build access, environment variable exposure, repository access, build manipulation",
    severity: "Medium",
    poc_template: "1. Use API token to access Travis CI\n2. List builds and repository configurations\n3. Access environment variables and logs\n4. Check build trigger capabilities",
    remediation: "Revoke API token and audit recent build activity"
  },

  "TeamCity": {
    service: "JetBrains TeamCity",
    category: "CI/CD Platform",
    impact: "Build configuration access, artifact manipulation, VCS integration abuse, agent control",
    severity: "High",
    poc_template: "1. Access TeamCity with exposed credentials\n2. View build configurations and parameters\n3. Check artifact dependencies and triggers\n4. Review agent pools and capabilities",
    remediation: "Change user credentials and audit build configuration changes"
  },

  // Container & Package Registries
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

  "PyPI": {
    service: "Python Package Index",
    category: "Package Registry",
    impact: "Python package publishing, supply chain attacks, package takeover, malicious code distribution",
    severity: "High",
    poc_template: "1. Authenticate with PyPI using API token\n2. List owned packages and permissions\n3. Check package upload capabilities\n4. Review download statistics and dependencies",
    remediation: "Revoke API token in PyPI account settings and audit recent uploads"
  },

  "RubyGems": {
    service: "RubyGems Package Registry",
    category: "Package Registry",
    impact: "Ruby gem publishing, supply chain attacks, gem takeover, dependency manipulation",
    severity: "High",
    poc_template: "1. Use API key to access RubyGems account\n2. List owned gems and permissions\n3. Check gem publishing capabilities\n4. Review gem statistics and versions",
    remediation: "Reset API key and audit recent gem publishing activity"
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

  "Segment": {
    service: "Segment Customer Data Platform",
    category: "Analytics Platform",
    impact: "Customer data access, event tracking exposure, destination configuration, PII data exposure",
    severity: "Medium",
    poc_template: "1. Use write key to send events to Segment\n2. Access workspace configuration with API token\n3. Review connected destinations and sources\n4. Check data governance and privacy settings",
    remediation: "Rotate API keys and write keys in Segment workspace settings"
  },

  "Amplitude": {
    service: "Amplitude Analytics",
    category: "Analytics Platform",
    impact: "User behavior analysis, event data access, cohort information, user journey tracking",
    severity: "Low",
    poc_template: "1. Use API key to access Amplitude data\n2. Query user events and properties\n3. Export behavioral analytics data\n4. Check user privacy and data retention settings",
    remediation: "Reset API key in Amplitude project settings"
  },

  // CDN & DNS Services
  "Cloudflare": {
    service: "Cloudflare DNS & CDN",
    category: "CDN/DNS Provider",
    impact: "DNS manipulation, domain hijacking, SSL certificate access, traffic routing abuse",
    severity: "High",
    poc_template: "1. Use API token to access Cloudflare account\n2. List managed domains and DNS records\n3. Check SSL certificate access\n4. Review firewall and security settings",
    remediation: "Revoke API token in Cloudflare dashboard and audit recent DNS changes"
  },

  "Fastly": {
    service: "Fastly CDN",
    category: "CDN Provider",
    impact: "CDN configuration access, cache manipulation, traffic routing, service disruption",
    severity: "Medium",
    poc_template: "1. Authenticate with Fastly API token\n2. List services and configurations\n3. Check cache settings and VCL configurations\n4. Review traffic analytics and logs",
    remediation: "Revoke API token and audit recent configuration changes"
  },

  "MaxCDN": {
    service: "MaxCDN/StackPath",
    category: "CDN Provider",
    impact: "CDN zone access, cache purging, traffic analytics, billing information access",
    severity: "Medium",
    poc_template: "1. Use API credentials to access MaxCDN account\n2. List CDN zones and configurations\n3. Check traffic statistics and bandwidth usage\n4. Test cache purging capabilities",
    remediation: "Reset API credentials and monitor traffic analytics for anomalies"
  },

  // File Storage & Cloud Storage
  "AmazonS3": {
    service: "Amazon S3 Storage",
    category: "Cloud Storage",
    impact: "Bucket access, data exfiltration, file manipulation, public exposure of private data",
    severity: "Critical",
    poc_template: "1. Configure AWS CLI with exposed credentials\n2. List accessible S3 buckets\n3. Download sample files as proof\n4. Check bucket policies and ACLs",
    remediation: "Rotate AWS credentials immediately and audit bucket access logs"
  },

  "GoogleDrive": {
    service: "Google Drive API",
    category: "File Storage",
    impact: "File access, document manipulation, sharing settings abuse, organizational data exposure",
    severity: "Medium",
    poc_template: "1. Use OAuth token to access Google Drive API\n2. List accessible files and folders\n3. Download sample documents\n4. Check sharing permissions and settings",
    remediation: "Revoke OAuth token and audit recent file access activity"
  },

  "Dropbox": {
    service: "Dropbox API",
    category: "File Storage",
    impact: "File system access, data exfiltration, sharing manipulation, team folder access",
    severity: "Medium",
    poc_template: "1. Use access token to connect to Dropbox API\n2. List files and folder structure\n3. Download sample files as proof\n4. Check sharing links and team access",
    remediation: "Revoke access token in Dropbox app console"
  },

  "Box": {
    service: "Box Cloud Storage",
    category: "File Storage",
    impact: "Enterprise file access, collaboration data, user information, folder structure exposure",
    severity: "Medium",
    poc_template: "1. Authenticate with Box API using credentials\n2. List accessible files and folders\n3. Check user information and collaborations\n4. Download sample files if permitted",
    remediation: "Revoke API credentials and audit recent file access logs"
  },

  // Search & API Services
  "Algolia": {
    service: "Algolia Search API",
    category: "Search Service",
    impact: "Search index access, data extraction, index manipulation, analytics data exposure",
    severity: "Medium",
    poc_template: "1. Use API key to access Algolia indices\n2. Query search data and retrieve records\n3. Check index configurations and settings\n4. Review search analytics and usage",
    remediation: "Regenerate API keys in Algolia dashboard"
  },

  "Elastic": {
    service: "Elastic Cloud",
    category: "Search/Analytics Engine",
    impact: "Cluster access, data indexing manipulation, search query access, performance metrics",
    severity: "High",
    poc_template: "1. Connect to Elastic cluster with credentials\n2. List indices and cluster health\n3. Query sample data from indices\n4. Check cluster settings and configurations",
    remediation: "Reset cluster credentials and enable security features"
  },

  // API Key Services
  "OpenAI": {
    service: "OpenAI API",
    category: "AI/ML Service",
    impact: "AI model access, token consumption abuse, generated content misuse, billing fraud",
    severity: "Medium",
    poc_template: "1. Use API key to access OpenAI endpoints\n2. Make sample API calls to verify access\n3. Check usage limits and billing information\n4. Test different model capabilities",
    remediation: "Revoke API key in OpenAI account settings and monitor usage"
  },

  "AnthropicClaude": {
    service: "Anthropic Claude API",
    category: "AI/ML Service",
    impact: "AI model access, conversation data exposure, API abuse, billing manipulation",
    severity: "Medium",
    poc_template: "1. Authenticate with Anthropic API key\n2. Send test prompts to Claude API\n3. Check conversation history and limits\n4. Review billing and usage statistics",
    remediation: "Reset API key and monitor usage for unauthorized activity"
  },

  "HuggingFace": {
    service: "Hugging Face API",
    category: "AI/ML Service",
    impact: "Model access, dataset manipulation, inference API abuse, private model exposure",
    severity: "Medium",
    poc_template: "1. Use API token to access Hugging Face Hub\n2. List accessible models and datasets\n3. Make inference API calls\n4. Check private repositories and organizations",
    remediation: "Revoke API token and audit model/dataset access"
  },

  // Geolocation & Maps
  "IPGeolocation": {
    service: "IPGeolocation",
    category: "Geolocation",
    impact: "Unauthorized access to geolocation information about IP addresses, potentially leading to excessive API usage charges or data scraping of location data.",
    severity: "Low",
    poc_template: "1. Locate exposed IPGeolocation API key.\n2. Use the key to retrieve geolocation data for an IP address via the IPGeolocation API.\n3. Verify successful data retrieval.",
    remediation: "Rotate the IPGeolocation API key immediately."
  },

  "GoogleMaps": {
    service: "Google Maps API",
    category: "Mapping Service",
    impact: "Map data access, geocoding abuse, route planning misuse, billing fraud",
    severity: "Low",
    poc_template: "1. Use API key to access Google Maps services\n2. Make geocoding and mapping requests\n3. Check Places API and routing capabilities\n4. Monitor API usage and quotas",
    remediation: "Restrict API key usage and regenerate in Google Cloud Console"
  },

  "Mapbox": {
    service: "Mapbox API",
    category: "Mapping Service",
    impact: "Map tile access, geocoding service abuse, navigation API misuse, usage quota exhaustion",
    severity: "Low",
    poc_template: "1. Use access token to query Mapbox APIs\n2. Retrieve map tiles and geocoding data\n3. Test navigation and routing services\n4. Check usage statistics and billing",
    remediation: "Revoke access token and create new one with proper restrictions"
  },

  // Communication & Collaboration
  "Slack": {
    service: "Slack Workspace",
    category: "Communication Platform",
    impact: "Internal communication access, sensitive data exfiltration, user impersonation, file downloads",
    severity: "High",
    poc_template: "1. Use bot token to access Slack API\n2. List channels and read message history\n3. Download shared files\n4. Access user profiles and contact information",
    remediation: "Revoke bot token in Slack app settings and audit channel access logs"
  },

  "Discord": {
    service: "Discord Bot API",
    category: "Communication Platform",
    impact: "Server access, message history, user data, voice channel access, bot permissions abuse",
    severity: "Medium",
    poc_template: "1. Use bot token to access Discord API\n2. List accessible servers and channels\n3. Read message history and user information\n4. Check bot permissions and capabilities",
    remediation: "Regenerate bot token in Discord Developer Portal"
  },

  "Zoom": {
    service: "Zoom API",
    category: "Video Conferencing",
    impact: "Meeting access, participant data, recording downloads, account information exposure",
    severity: "Medium",
    poc_template: "1. Use JWT or OAuth to access Zoom API\n2. List meetings and webinars\n3. Access participant information and settings\n4. Check recording and transcript access",
    remediation: "Revoke API credentials and audit recent meeting activity"
  },

  "MicrosoftTeams": {
    service: "Microsoft Teams API",
    category: "Communication Platform",
    impact: "Team communication access, file sharing exposure, calendar integration, user directory access",
    severity: "High",
    poc_template: "1. Use access token for Microsoft Graph API\n2. Access Teams messages and channel data\n3. List team members and permissions\n4. Check file sharing and calendar integration",
    remediation: "Revoke OAuth tokens and audit app permissions in Azure AD"
  },

  // Customer Support & CRM
  "Zendesk": {
    service: "Zendesk Support Platform",
    category: "Customer Support",
    impact: "Customer ticket access, personal information exposure, support agent data, knowledge base access",
    severity: "High",
    poc_template: "1. Use API token to access Zendesk instance\n2. List customer tickets and comments\n3. Access user profiles and agent information\n4. Check knowledge base articles and macros",
    remediation: "Deactivate API token and audit recent support activity"
  },

  "Intercom": {
    service: "Intercom Customer Platform",
    category: "Customer Support",
    impact: "Customer conversation access, user data exposure, automation settings, team member information",
    severity: "High",
    poc_template: "1. Authenticate with Intercom API token\n2. Access customer conversations and profiles\n3. List team members and workspace settings\n4. Check automation rules and data attributes",
    remediation: "Revoke API token and audit customer data access"
  },

  "Salesforce": {
    service: "Salesforce CRM",
    category: "CRM Platform",
    impact: "Customer data access, sales pipeline exposure, contact information, financial data, opportunity details",
    severity: "Critical",
    poc_template: "1. Use OAuth or session ID to access Salesforce API\n2. Query customer and lead information\n3. Access opportunity and account data\n4. Check user permissions and org settings",
    remediation: "Revoke OAuth tokens and reset session, audit data access logs"
  },

  "HubSpot": {
    service: "HubSpot CRM",
    category: "CRM Platform",
    impact: "Contact database access, marketing automation exposure, sales pipeline data, email campaign access",
    severity: "High",
    poc_template: "1. Use API key to access HubSpot account\n2. List contacts and company information\n3. Access deals and marketing campaigns\n4. Check automation workflows and settings",
    remediation: "Regenerate API key and audit recent CRM activity"
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
    
    poc: `**Proof of Concept:**\n\n${intelligence.poc_template}\n\n**Location Details:**\n- Repository: ${secretData.repo_url}\n- File: ${secretData.file_path}\n- Commit URL: ${commitUrl}\n- Secret: ${secretData.raw_secret || 'N/A'}`,
    
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
