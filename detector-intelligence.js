const DETECTOR_INTELLIGENCE = {

  "APIMatic": {
    "service": "APIMatic",
    "category": "API Tooling",
    "impact": "Unauthorized generation and management of SDKs, API documentation, and code snippets, potentially leading to exposure of API functionalities or sensitive code.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed APIMatic credentials.\n2. Attempt to use the credentials to access APIMatic's dashboard or API.\n3. Verify ability to generate or modify an SDK/documentation.",
    "remediation": "Rotate APIMatic credentials immediately."
  },
  "IPGeolocation": {
    "service": "IPGeolocation",
    "category": "Geolocation",
    "impact": "Unauthorized access to geolocation information about IP addresses, potentially leading to excessive API usage charges or data scraping of location data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed IPGeolocation API key.\n2. Use the key to retrieve geolocation data for an IP address via the IPGeolocation API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the IPGeolocation API key immediately."
  },
  "APITemplate": {
    "service": "APITemplate",
    "category": "Document/Image Generation",
    "impact": "Unauthorized generation of documents and images from templates, potentially leading to the creation of malicious content, phishing attempts, or exposure of sensitive data used in templates.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed APITemplate API key.\n2. Attempt to make a request to the APITemplate API to generate a document or image.\n3. Verify successful generation and access to the output.",
    "remediation": "Regenerate APITemplate API keys immediately."
  },
  "AWS": {
    "service": "Amazon Web Services",
    "category": "Cloud Provider",
    "impact": "Complete AWS account access, resource manipulation, billing fraud, data exfiltration from S3/RDS/EC2",
    "severity": "Critical",
    "poc_template": "1. Locate exposed AWS credentials\n2. Configure AWS CLI with found credentials\n3. Run 'aws sts get-caller-identity' to verify access\n4. Enumerate accessible resources with 'aws s3 ls' or 'aws ec2 describe-instances'",
    "remediation": "Immediately rotate credentials in AWS IAM Console and review CloudTrail logs for unauthorized access"
  },
  "AWSSessionKey": {
    "service": "Amazon Web Services",
    "category": "Cloud Provider",
    "impact": "Temporary but potentially significant access to AWS resources, allowing for data exfiltration, resource modification, or service disruption during the session key's validity.",
    "severity": "High",
    "poc_template": "1. Locate exposed AWS session key.\n2. Configure AWS CLI with the found session key, access key, and secret key.\n3. Run 'aws sts get-caller-identity' to verify temporary access.\n4. Enumerate accessible resources.",
    "remediation": "Invalidate the exposed AWS session key if possible, and review AWS CloudTrail logs for any unauthorized actions during the key's validity."
  },
  "AbuseIPDB": {
    "service": "AbuseIPDB",
    "category": "Security & Threat Intelligence",
    "impact": "Unauthorized reporting of IP addresses, potentially leading to false positives or abuse of the service. Also, unauthorized checking of IP addresses could expose internal network information or reconnaissance efforts.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed AbuseIPDB API key.\n2. Use the key to query a known IP address or attempt to report an IP address via the AbuseIPDB API.\n3. Verify successful interaction with the API.",
    "remediation": "Revoke and regenerate the AbuseIPDB API key immediately."
  },
  "Abyssale": {
    "service": "Abyssale",
    "category": "Marketing & Automation",
    "impact": "Unauthorized access to and manipulation of marketing automation data, including the creation of images and ad campaigns, potentially leading to brand damage or misuse of marketing resources.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Abyssale API key.\n2. Attempt to use the key to access or create a resource (e.g., an image) via the Abyssale API.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Abyssale API key immediately."
  },
  "Accuweather": {
    "service": "AccuWeather",
    "category": "Weather & Environmental Data",
    "impact": "Unauthorized access to weather data and forecasts, potentially leading to excessive API usage charges or the exploitation of data for unintended purposes.",
    "severity": "Low",
    "poc_template": "1. Locate exposed AccuWeather API key.\n2. Use the key to fetch weather data for a specific location via the AccuWeather API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the AccuWeather API key immediately."
  },
  "AdafruitIO": {
    "service": "Adafruit IO",
    "category": "IoT & Cloud Services",
    "impact": "Unauthorized access and control over IoT devices and data connected to Adafruit IO, potentially leading to device manipulation, data theft, or service disruption.",
    "severity": "High",
    "poc_template": "1. Locate exposed Adafruit IO key.\n2. Use the key to access a feed or control a device connected to Adafruit IO via their API.\n3. Verify successful interaction and data access/control.",
    "remediation": "Revoke the exposed Adafruit IO key and generate a new one immediately."
  },
  "Adzuna": {
    "service": "Adzuna",
    "category": "Job Search & Data",
    "impact": "Unauthorized access to job listing data, potentially leading to data scraping or misuse of job market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Adzuna API key.\n2. Use the key to query job listings via the Adzuna API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Adzuna API key immediately."
  },
  "Aeroworkflow": {
    "service": "Aeroworkflow",
    "category": "Workflow Management",
    "impact": "Unauthorized access and management of workflows, potentially leading to disruption of business processes, data manipulation, or exposure of sensitive workflow configurations.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Aeroworkflow API key and Account ID.\n2. Attempt to list or modify workflows using the found credentials via the Aeroworkflow API.\n3. Verify successful interaction.",
    "remediation": "Revoke and regenerate Aeroworkflow API keys and ensure Account IDs are kept confidential."
  },
  "Agora": {
    "service": "Agora",
    "category": "Real-time Communication",
    "impact": "Unauthorized access and management of real-time communication services (voice, video, messaging), potentially leading to eavesdropping, unauthorized communication, or service disruption.",
    "severity": "High",
    "poc_template": "1. Locate exposed Agora API key.\n2. Attempt to create or join a real-time communication session using the Agora API with the found key.\n3. Verify successful session initiation or management.",
    "remediation": "Revoke and regenerate the Agora API key immediately."
  },
  "Aha": {
    "service": "Aha",
    "category": "Product Management",
    "impact": "Unauthorized access to and modification of product data and workflows, potentially leading to intellectual property theft, product roadmap exposure, or disruption of product development.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Aha API key.\n2. Attempt to retrieve or modify product data (e.g., features, initiatives) using the Aha API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Aha API key immediately."
  },
  "AirVisual": {
    "service": "AirVisual",
    "category": "Air Quality Data",
    "impact": "Unauthorized access to air quality data, potentially leading to misuse of information or excessive API usage charges.",
    "severity": "Low",
    "poc_template": "1. Locate exposed AirVisual API key.\n2. Use the key to query air quality data for a location via the AirVisual API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the AirVisual API key immediately."
  },
  "AirbrakeProjectKey": {
    "service": "Airbrake",
    "category": "Error Monitoring",
    "impact": "Unauthorized reporting of errors and performance data, potentially leading to the injection of false error reports or consumption of API quotas.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Airbrake project key.\n2. Attempt to send a test error report to Airbrake using the found project key.\n3. Verify the error appears in the Airbrake dashboard (if accessible).",
    "remediation": "Rotate the Airbrake project key immediately."
  },
  "AirbrakeUserKey": {
    "service": "Airbrake",
    "category": "Error Monitoring",
    "impact": "Unauthorized access to and management of error reports and performance data, potentially exposing sensitive application issues or allowing an attacker to manipulate monitoring data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Airbrake user key.\n2. Attempt to access or modify error reports or project settings using the Airbrake API with the found user key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Airbrake user key and generate a new one immediately."
  },
  "Airship": {
    "service": "Airship",
    "category": "Customer Engagement",
    "impact": "Unauthorized access to and management of customer engagement campaigns, including mobile app messaging, in-app messages, and web notifications, potentially leading to spamming, phishing, or brand impersonation.",
    "severity": "High",
    "poc_template": "1. Locate exposed Airship API key.\n2. Attempt to send a test notification or access campaign data using the Airship API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Airship API key immediately."
  },
  "AirtableApiKey": {
    "service": "Airtable",
    "category": "Cloud Collaboration & Database",
    "impact": "Unauthorized access to and modification of data within Airtable bases, potentially leading to data theft, data corruption, or unauthorized data exposure.",
    "severity": "High",
    "poc_template": "1. Locate exposed Airtable API key.\n2. Use the key to list or modify records in an accessible Airtable base via the Airtable API.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the Airtable API key immediately and generate a new one, ensuring it's stored securely."
  },
  "AirtableOAuth": {
    "service": "Airtable",
    "category": "Cloud Collaboration & Database",
    "impact": "Unauthorized access to and modification of data within Airtable bases on behalf of a user, potentially leading to data theft, data corruption, or unauthorized data exposure.",
    "severity": "High",
    "poc_template": "1. Locate exposed Airtable OAuth token.\n2. Use the token to list or modify records in an accessible Airtable base via the Airtable API on behalf of the authorized user.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the Airtable OAuth token immediately and re-authorize the application if necessary."
  },
  "AirtablePersonalAccessToken": {
    "service": "Airtable",
    "category": "Cloud Collaboration & Database",
    "impact": "Unauthorized access to and modification of data within Airtable bases on behalf of the user who generated the token, potentially leading to data theft, data corruption, or unauthorized data exposure.",
    "severity": "High",
    "poc_template": "1. Locate exposed Airtable Personal Access Token.\n2. Use the token to list or modify records in an accessible Airtable base via the Airtable API.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the Airtable Personal Access Token immediately and generate a new one, storing it securely."
  },
  "Aiven": {
    "service": "Aiven",
    "category": "Managed Cloud Services",
    "impact": "Unauthorized access to and management of managed cloud data infrastructure services (e.g., Kafka, PostgreSQL, Redis), potentially leading to data compromise, service disruption, or resource abuse.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Aiven API key.\n2. Attempt to list or manage Aiven services (e.g., create a new database) using the Aiven API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Aiven API key immediately."
  },
  "Alchemy": {
    "service": "Alchemy",
    "category": "Blockchain Development",
    "impact": "Unauthorized access to and manipulation of blockchain development tools and services, potentially leading to unauthorized transactions, data exposure on the blockchain, or disruption of decentralized applications.",
    "severity": "High",
    "poc_template": "1. Locate exposed Alchemy API key.\n2. Attempt to make a request to an Alchemy endpoint (e.g., retrieve transaction data, interact with a smart contract) using the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Alchemy API key immediately."
  },
  "Alegra": {
    "service": "Alegra",
    "category": "Accounting Software",
    "impact": "Unauthorized access to and modification of accounting data and user information, potentially leading to financial fraud, data manipulation, or exposure of sensitive financial records.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Alegra API key.\n2. Attempt to retrieve or modify accounting data (e.g., invoices, contacts) using the Alegra API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Alegra API key immediately."
  },
  "AletheiaApi": {
    "service": "AletheiaApi",
    "category": "Financial Data",
    "impact": "Unauthorized access to financial data, potentially leading to data scraping, competitive intelligence gathering, or exploitation of market information.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed AletheiaApi key.\n2. Use the key to query financial data via the AletheiaApi.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the AletheiaApi key immediately."
  },
  "AlgoliaAdminKey": {
    "service": "Algolia",
    "category": "Search-as-a-Service",
    "impact": "Complete administrative control over Algolia indices and API keys, allowing for data modification, deletion, injection of malicious search results, or creation of new administrative keys, leading to severe data integrity and security risks.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Algolia Admin Key.\n2. Use the key to list existing indices or create a new API key via the Algolia API.\n3. Verify successful administrative action.",
    "remediation": "Immediately revoke the exposed Algolia Admin Key and generate a new one. Review all Algolia activities for any unauthorized changes."
  },
  "Alibaba": {
    "service": "Alibaba Cloud",
    "category": "Cloud Provider",
    "impact": "Complete Alibaba Cloud account access, resource manipulation, billing fraud, data exfiltration from storage/databases.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Alibaba Cloud API keys.\n2. Configure Alibaba Cloud CLI with found credentials.\n3. Attempt to list or manage cloud resources (e.g., OSS buckets, ECS instances).\n4. Verify successful access and resource enumeration.",
    "remediation": "Immediately rotate credentials in Alibaba Cloud console and review action logs for unauthorized access."
  },
  "AlienVault": {
    "service": "AlienVault",
    "category": "Threat Intelligence",
    "impact": "Unauthorized access to threat data and other security services, potentially leading to the leakage of threat intelligence, misuse of security tools, or disruption of security operations.",
    "severity": "High",
    "poc_template": "1. Locate exposed AlienVault API key.\n2. Use the key to query threat data or interact with AlienVault services via their API.\n3. Verify successful data retrieval or service interaction.",
    "remediation": "Revoke and regenerate the AlienVault API key immediately."
  },
  "Allsports": {
    "service": "Allsports",
    "category": "Sports Data",
    "impact": "Unauthorized access to sports data, potentially leading to data scraping or misuse of sports information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Allsports API key.\n2. Use the key to fetch sports data via the Allsports API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Allsports API key immediately."
  },
  "Amadeus": {
    "service": "Amadeus",
    "category": "Travel Technology",
    "impact": "Unauthorized access to and modification of travel-related data and services, potentially leading to booking manipulation, access to traveler information, or fraud.",
    "severity": "High",
    "poc_template": "1. Locate exposed Amadeus API key.\n2. Attempt to search for flights, book tickets, or access traveler data using the Amadeus API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Amadeus API key immediately."
  },
  "Ambee": {
    "service": "Ambee",
    "category": "Environmental & Climate Data",
    "impact": "Unauthorized access to environmental and climate data, potentially leading to excessive API usage charges or the exploitation of data for unintended purposes.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Ambee API key.\n2. Use the key to fetch environmental data for a specific location via the Ambee API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Ambee API key immediately."
  },
  "AmplitudeApiKey": {
    "service": "Amplitude",
    "category": "Product Analytics",
    "impact": "Unauthorized access to and modification of product analytics data, potentially leading to the injection of false data, data exfiltration, or disruption of analytics reporting.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Amplitude API key.\n2. Use the key to query or modify user behavior data via the Amplitude API.\n3. Verify successful data interaction.",
    "remediation": "Revoke and regenerate the Amplitude API key immediately."
  },
  "Anthropic": {
    "service": "Anthropic",
    "category": "AI Services",
    "impact": "Unauthorized access to and usage of Anthropic's AI models and services, potentially leading to resource abuse, generation of harmful content, or exposure of proprietary AI interactions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Anthropic API key.\n2. Attempt to make a request to an Anthropic AI model (e.g., generate text) using the found key.\n3. Verify successful API interaction and response.",
    "remediation": "Revoke and regenerate the Anthropic API key immediately."
  },
  "Anypoint": {
    "service": "Anypoint",
    "category": "API Management & Integration",
    "impact": "Unauthorized access to and manipulation of APIs and integrations, potentially leading to data breaches, service disruptions, or unauthorized modification of business processes.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Anypoint credentials.\n2. Attempt to access the Anypoint platform or API to list/modify APIs or integrations.\n3. Verify successful administrative access.",
    "remediation": "Revoke and regenerate Anypoint credentials immediately. Review all audit logs for unauthorized activities."
  },
  "Apacta": {
    "service": "Apacta",
    "category": "Project Management",
    "impact": "Unauthorized access to and management of project data in the construction industry, potentially leading to project disruption, data theft, or exposure of sensitive project details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Apacta API key.\n2. Attempt to retrieve or modify project data using the Apacta API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Apacta API key immediately."
  },
  "Api2Cart": {
    "service": "Api2Cart",
    "category": "E-commerce Integration",
    "impact": "Unauthorized access to and manipulation of shopping cart data across multiple platforms, potentially leading to order manipulation, customer data theft, or financial fraud.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Api2Cart API key.\n2. Attempt to list or modify shopping cart data from a connected platform using the Api2Cart API.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Api2Cart API key immediately."
  },
  "ApiDeck": {
    "service": "ApiDeck",
    "category": "API Integration Platform",
    "impact": "Unauthorized access to and management of multiple integrated services, potentially leading to data breaches, service disruptions, or unauthorized actions across connected platforms.",
    "severity": "High",
    "poc_template": "1. Locate exposed ApiDeck key.\n2. Attempt to list or manage connected services via the ApiDeck API using the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the ApiDeck key immediately."
  },
  "ApiFonica": {
    "service": "Apifonica",
    "category": "Cloud Communication",
    "impact": "Unauthorized access to and management of messaging, voice, and other communication services, potentially leading to unauthorized calls/messages, eavesdropping, or service disruption.",
    "severity": "High",
    "poc_template": "1. Locate exposed Apifonica key.\n2. Attempt to send a test message or initiate a call using the Apifonica API with the found key.\n3. Verify successful communication.",
    "remediation": "Revoke and regenerate the Apifonica key immediately."
  },
  "ApiMetrics": {
    "service": "ApiMetrics",
    "category": "API Monitoring",
    "impact": "Unauthorized access to and management of API monitoring configurations, potentially leading to disabling monitoring, altering alerts, or exposing sensitive API performance data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ApiMetrics key.\n2. Attempt to list or modify API monitors using the ApiMetrics API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the ApiMetrics key immediately."
  },
  "Apiflash": {
    "service": "Apiflash",
    "category": "Screenshot Service",
    "impact": "Unauthorized utilization of screenshot API service, potentially leading to excessive API usage charges or the generation of unauthorized screenshots (e.g., internal web pages).",
    "severity": "Low",
    "poc_template": "1. Locate exposed Apiflash key.\n2. Use the key to generate a screenshot of a public webpage via the Apiflash API.\n3. Verify successful screenshot generation.",
    "remediation": "Rotate the Apiflash key immediately."
  },
  "Apify": {
    "service": "Apify",
    "category": "Web Scraping & Automation",
    "impact": "Unauthorized access and control over web scraping actors and tasks, potentially leading to data exfiltration, resource abuse, or execution of malicious scraping operations.",
    "severity": "High",
    "poc_template": "1. Locate exposed Apify API key.\n2. Attempt to list or run an Apify actor or task using the Apify API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Apify API key immediately."
  },
  "Apilayer": {
    "service": "Apilayer",
    "category": "Data Verification & Utilities",
    "impact": "Unauthorized access to various data verification services (e.g., number verification, IP geolocation), potentially leading to misuse of verification services or data exposure.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Apilayer API key.\n2. Use the key to perform a number verification or another utility function via the Apilayer API.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Apilayer API key immediately."
  },
  "AppOptics": {
    "service": "AppOptics",
    "category": "Infrastructure Monitoring",
    "impact": "Unauthorized access to and management of infrastructure monitoring data and configurations, potentially leading to disabling monitoring, altering alerts, or exposing sensitive system performance data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed AppOptics API key.\n2. Attempt to list or modify monitoring configurations or metrics using the AppOptics API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the AppOptics API key immediately."
  },
  "AppSynergy": {
    "service": "AppSynergy",
    "category": "Cloud Application Development",
    "impact": "Unauthorized access to and management of cloud applications and data, potentially leading to data breaches, application manipulation, or unauthorized resource usage.",
    "severity": "High",
    "poc_template": "1. Locate exposed AppSynergy API key.\n2. Attempt to list or modify applications/data within the AppSynergy platform using the API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the AppSynergy API key immediately."
  },
  "Appcues": {
    "service": "Appcues",
    "category": "User Engagement",
    "impact": "Unauthorized access to and management of user engagement flows and data, potentially leading to unauthorized in-app messages, misleading user experiences, or exposure of user engagement analytics.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Appcues credentials.\n2. Attempt to access or modify user engagement flows or data using the Appcues API.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate Appcues credentials immediately."
  },
  "Appfollow": {
    "service": "Appfollow",
    "category": "App Monitoring & Analytics",
    "impact": "Unauthorized access to and management of app data and analytics, potentially leading to exposure of sensitive app performance metrics, review data, or competitive intelligence.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Appfollow API token.\n2. Attempt to retrieve app analytics data or manage app configurations using the Appfollow API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Appfollow API token immediately."
  },
  "Appointedd": {
    "service": "Appointedd",
    "category": "Online Booking & Scheduling",
    "impact": "Unauthorized access to and management of booking data, potentially leading to appointment manipulation, exposure of sensitive customer information, or disruption of scheduling services.",
    "severity": "High",
    "poc_template": "1. Locate exposed Appointedd API key.\n2. Attempt to list or modify booking data using the Appointedd API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Appointedd API key immediately."
  },
  "Apptivo": {
    "service": "Apptivo",
    "category": "Business Management Software",
    "impact": "Unauthorized access to and management of various business solutions including CRM, project management, and more, potentially leading to data breaches, workflow disruption, or financial fraud.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Apptivo API key.\n2. Attempt to retrieve or modify data in a core Apptivo module (e.g., CRM contacts, project tasks) using the Apptivo API.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Apptivo API key immediately."
  },
  "Artsy": {
    "service": "Artsy",
    "category": "Art Platform",
    "impact": "Unauthorized access to Artsy's services and data, potentially leading to data scraping of art listings, artist information, or other platform data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Artsy API key.\n2. Use the key to query art listings or artist data via the Artsy API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Artsy API key immediately."
  },
  "AsanaOauth": {
    "service": "Asana",
    "category": "Work Management",
    "impact": "Unauthorized access to and manipulation of work management data (tasks, projects, teams) on behalf of a user, potentially leading to disruption of work, data exfiltration, or unauthorized task assignments.",
    "severity": "High",
    "poc_template": "1. Locate exposed Asana OAuth token.\n2. Attempt to list or modify tasks/projects using the Asana API with the found token on behalf of the authorized user.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the Asana OAuth token immediately and re-authorize the application if necessary."
  },
  "AsanaPersonalAccessToken": {
    "service": "Asana",
    "category": "Work Management",
    "impact": "Unauthorized access to and modification of work management data (tasks, projects, teams) on behalf of the user who generated the token, potentially leading to disruption of work, data exfiltration, or unauthorized task assignments.",
    "severity": "High",
    "poc_template": "1. Locate exposed Asana Personal Access Token.\n2. Attempt to list or modify tasks/projects using the Asana API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the Asana Personal Access Token immediately and generate a new one, storing it securely."
  },
  "AssemblyAI": {
    "service": "AssemblyAI",
    "category": "Speech-to-Text",
    "impact": "Unauthorized utilization of speech-to-text transcription services, potentially leading to excessive API usage charges or the transcription of sensitive audio without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed AssemblyAI key.\n2. Attempt to transcribe an audio file using the AssemblyAI API with the found key.\n3. Verify successful transcription.",
    "remediation": "Rotate the AssemblyAI key immediately."
  },
  "Atera": {
    "service": "Atera",
    "category": "IT Management",
    "impact": "Unauthorized access to and management of IT resources, including alerts, tickets, and devices, potentially leading to IT system disruption, sensitive data exposure, or unauthorized remote access.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Atera API key.\n2. Attempt to list or manage IT resources (e.g., tickets, devices) using the Atera API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Atera API key immediately."
  },
  "Atlassian": {
    "service": "Atlassian",
    "category": "Project Management & Collaboration",
    "impact": "Unauthorized access to and management of Atlassian tools (e.g., Jira, Confluence, Bitbucket), potentially leading to intellectual property theft, project disruption, code modification, or exposure of sensitive collaboration data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Atlassian token.\n2. Attempt to access or modify data within a connected Atlassian product (e.g., list Jira issues, view Confluence pages) using the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Atlassian token immediately and generate a new one. Review audit logs for unauthorized access."
  },
  "Audd": {
    "service": "Audd",
    "category": "Music Recognition",
    "impact": "Unauthorized utilization of music recognition services, potentially leading to excessive API usage charges or the recognition of copyrighted material without consent.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Audd API token.\n2. Attempt to recognize a music sample using the Audd API with the found token.\n3. Verify successful recognition.",
    "remediation": "Rotate the Audd API token immediately."
  },
  "Auth0ManagementApiToken": {
    "service": "Auth0",
    "category": "Authentication & Authorization",
    "impact": "Complete administrative control over Auth0 tenants, allowing for user account manipulation, role and permission changes, and access to sensitive authentication configurations, leading to severe security compromises.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Auth0 Management API token.\n2. Attempt to list users or modify a user's role via the Auth0 Management API with the found token.\n3. Verify successful administrative action.",
    "remediation": "Immediately revoke the exposed Auth0 Management API token and generate a new one. Review Auth0 logs for any unauthorized changes."
  },
  "Auth0oauth": {
    "service": "Auth0",
    "category": "Authentication & Authorization",
    "impact": "Unauthorized impersonation of applications and access to user data or protected resources via Auth0's API, potentially leading to data breaches or unauthorized access to integrated services.",
    "severity": "High",
    "poc_template": "1. Locate exposed Auth0 OAuth API key.\n2. Attempt to perform an action (e.g., retrieve user profile) on behalf of an application using the Auth0 API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Auth0 OAuth API key immediately."
  },
  "AutoPilot": {
    "service": "AutoPilot",
    "category": "Marketing Automation",
    "impact": "Unauthorized access to and management of marketing data and campaigns, potentially leading to unauthorized email sending, lead manipulation, or exposure of sensitive customer data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed AutoPilot API key.\n2. Attempt to list or modify marketing campaigns or contacts using the AutoPilot API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the AutoPilot API key immediately."
  },
  "Autodesk": {
    "service": "Autodesk",
    "category": "Design & Engineering Software",
    "impact": "Unauthorized access to and modification of data within Autodesk services, potentially leading to intellectual property theft, design manipulation, or disruption of engineering workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Autodesk API key.\n2. Attempt to list or modify design data (e.g., models, drawings) using the Autodesk API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Autodesk API key immediately."
  },
  "Autoklose": {
    "service": "Autoklose",
    "category": "Sales Automation",
    "impact": "Unauthorized access to and management of sales automation campaigns, contacts, and related data, potentially leading to unauthorized email outreach, lead theft, or exposure of sales strategies.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Autoklose API token.\n2. Attempt to list or modify sales campaigns or contacts using the Autoklose API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Autoklose API token immediately."
  },
  "AvazaPersonalAccessToken": {
    "service": "Avaza",
    "category": "Business Management Software",
    "impact": "Unauthorized access to and manipulation of project management, time tracking, and financial data on behalf of a user, potentially leading to project disruption, financial fraud, or data exfiltration.",
    "severity": "High",
    "poc_template": "1. Locate exposed Avaza Personal Access Token.\n2. Attempt to list or modify project tasks or time entries using the Avaza API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the Avaza Personal Access Token immediately and generate a new one, storing it securely."
  },
  "AviationStack": {
    "service": "AviationStack",
    "category": "Aviation Data",
    "impact": "Unauthorized access to real-time flight status and aviation data, potentially leading to excessive API usage charges or misuse of flight information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed AviationStack API key.\n2. Use the key to fetch flight status for a known flight via the AviationStack API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the AviationStack API key immediately."
  },
  "Axonaut": {
    "service": "Axonaut",
    "category": "Business Management Software",
    "impact": "Unauthorized access to and management of business data including CRM, invoicing, and accounting, potentially leading to data breaches, financial fraud, or operational disruption.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Axonaut API key.\n2. Attempt to retrieve or modify business data (e.g., customer details, invoices) using the Axonaut API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Axonaut API key immediately."
  },
  "Aylien": {
    "service": "Aylien",
    "category": "Text Analysis & NLP",
    "impact": "Unauthorized utilization of natural language processing and machine learning APIs, potentially leading to excessive API usage charges or the processing of sensitive text data without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Aylien API key.\n2. Attempt to perform text analysis (e.g., sentiment analysis) on a sample text using the Aylien API with the found key.\n3. Verify successful analysis.",
    "remediation": "Rotate the Aylien API key immediately."
  },
  "Ayrshare": {
    "service": "Ayrshare",
    "category": "Social Media Management",
    "impact": "Unauthorized access to and management of social media accounts and posts, potentially leading to unauthorized posting, account impersonation, or exposure of social media strategies.",
    "severity": "High",
    "poc_template": "1. Locate exposed Ayrshare API key.\n2. Attempt to list or create a social media post using the Ayrshare API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Ayrshare API key immediately."
  },
  "Azure": {
    "service": "Azure",
    "category": "Cloud Provider",
    "impact": "Complete Azure account access, resource manipulation, billing fraud, data exfiltration from storage/databases.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure credentials.\n2. Configure Azure CLI/PowerShell with found credentials.\n3. Run 'az account show' or similar to verify access.\n4. Enumerate accessible resources with 'az storage account list' or 'az vm list'.",
    "remediation": "Immediately rotate credentials in Azure portal and review Azure Activity Logs for unauthorized access."
  },
  "AzureAPIManagementSubscriptionKey": {
    "service": "Azure API Management",
    "category": "Cloud Provider (API Management)",
    "impact": "Unauthorized access to and manipulation of API Management entities (users, groups, products, subscriptions), potentially leading to unauthorized API access, policy changes, or service disruption.",
    "severity": "High",
    "poc_template": "1. Locate exposed Azure API Management Subscription Key.\n2. Attempt to list users or products within the Azure API Management instance using the Management REST API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Azure API Management Subscription Key immediately."
  },
  "AzureApiManagementRepositoryKey": {
    "service": "Azure API Management",
    "category": "Cloud Provider (API Management)",
    "impact": "Direct access to modify API definitions, policies, and settings within Azure API Management via its Git repository. This could lead to unauthorized API changes, policy injection, or service misconfiguration, severely impacting API security and functionality.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure API Management Repository Key.\n2. Attempt to clone the API Management configuration repository using Git with the found key.\n3. Verify successful repository access and the ability to modify files.",
    "remediation": "Immediately revoke the exposed Azure API Management Repository Key and generate a new one. Review all repository activity for unauthorized changes."
  },
  "AzureAppConfigConnectionString": {
    "service": "Azure App Configuration",
    "category": "Cloud Provider (Configuration Management)",
    "impact": "Unauthorized access to and modification of application settings and feature flags, allowing an attacker to alter application behavior, enable/disable features, or inject malicious configurations, leading to application compromise or data exposure.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure App Configuration Connection String.\n2. Use the connection string to connect to the App Configuration store via Azure CLI or SDK.\n3. Attempt to read or modify a configuration setting.\n4. Verify successful access and modification.",
    "remediation": "Immediately rotate the access keys associated with the exposed Azure App Configuration connection string and regenerate the string. Review Azure Monitor logs for any unauthorized access."
  },
  "AzureBatch": {
    "service": "Azure Batch",
    "category": "Cloud Provider (Compute)",
    "impact": "Unauthorized access to and management of large-scale parallel and high-performance computing resources, potentially leading to resource abuse (e.g., cryptocurrency mining), denial of service, or exposure of sensitive computational data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Azure Batch account key.\n2. Attempt to list or manage Batch pools/jobs using the Azure Batch API with the found key.\n3. Verify successful API interaction and resource access.",
    "remediation": "Rotate the Azure Batch account key immediately."
  },
  "AzureContainerRegistry": {
    "service": "Azure Container Registry",
    "category": "Cloud Provider (Containerization)",
    "impact": "Unauthorized access to Docker containers, potentially allowing attackers to override existing containers with malicious images, read sensitive data from containers, or inject vulnerabilities into deployed applications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure Container Registry API key.\n2. Attempt to log in to the container registry using 'docker login' with the found key.\n3. Verify successful authentication and ability to pull/push images.",
    "remediation": "Immediately rotate the Azure Container Registry API key and review audit logs for unauthorized access or image modifications."
  },
  "AzureCosmosDBKeyIdentifiable": {
    "service": "Azure Cosmos DB",
    "category": "Cloud Provider (Database)",
    "impact": "Unauthorized access to and modification of globally distributed, multi-model database data, potentially leading to data theft, data corruption, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure Cosmos DB key or connection string.\n2. Use the key/connection string to connect to the Cosmos DB instance via SDK or Azure CLI.\n3. Attempt to list or query data within a database/collection.\n4. Verify successful data access and manipulation.",
    "remediation": "Immediately rotate the Azure Cosmos DB keys and review Cosmos DB diagnostic logs for unauthorized access."
  },
  "AzureDevopsPersonalAccessToken": {
    "service": "Azure DevOps",
    "category": "DevOps Platform",
    "impact": "Unauthorized access to and management of Azure DevOps services and resources (e.g., source code repositories, build pipelines, work items), potentially leading to intellectual property theft, code injection, or disruption of software development workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure DevOps Personal Access Token (PAT).\n2. Attempt to use the PAT to access a repository, build pipeline, or work item via the Azure DevOps API.\n3. Verify successful API interaction and resource access.",
    "remediation": "Revoke the Azure DevOps Personal Access Token immediately and generate a new one, ensuring it has minimal necessary permissions and a short lifespan."
  },
  "AzureDirectManagementKey": {
    "service": "Azure API Management",
    "category": "Cloud Provider (API Management)",
    "impact": "Direct administrative access to Azure API Management entities (users, groups, products, subscriptions), allowing for full control over API configurations, user access, and policies, potentially leading to unauthorized API exposure, policy injection, or service disruption.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure Direct Management Key.\n2. Attempt to list users, create new products, or modify policies within the Azure API Management instance using the Management REST API with the found key.\n3. Verify successful administrative action.",
    "remediation": "Immediately revoke the exposed Azure Direct Management Key and generate a new one. Review Azure API Management activity logs for any unauthorized changes."
  },
  "AzureOpenAIAzure": {
    "service": "Azure OpenAI",
    "category": "AI Services",
    "impact": "Unauthorized access to and usage of Azure OpenAI models and services, potentially leading to resource abuse, generation of harmful content, or exposure of proprietary AI interactions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Azure OpenAI API key.\n2. Attempt to make a request to an Azure OpenAI model (e.g., generate text, complete a prompt) using the found key.\n3. Verify successful API interaction and response.",
    "remediation": "Revoke and regenerate the Azure OpenAI API key immediately."
  },
  "AzureRefreshToken": {
    "service": "Azure Entra ID",
    "category": "Cloud Provider (Identity & Access Management)",
    "impact": "Long-lasting unauthorized access to an Azure account, allowing an attacker to impersonate the user and access various Azure resources and integrated applications, potentially leading to widespread data breaches or system compromise.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure Entra ID refresh token.\n2. Attempt to exchange the refresh token for an access token to gain access to Azure resources or services via OAuth flow.\n3. Verify successful token exchange and resource access.",
    "remediation": "Force a password reset for the affected Azure Entra ID user and revoke all refresh tokens. Implement conditional access policies and multi-factor authentication."
  },
  "AzureSasToken": {
    "service": "Azure Storage",
    "category": "Cloud Provider (Storage)",
    "impact": "Secure, granular, but potentially unauthorized access to specific Azure Storage resources (blobs, containers, files) for a limited time, allowing data reading, writing, or deletion depending on the permissions granted by the token, without exposing account keys.",
    "severity": "High",
    "poc_template": "1. Locate exposed Azure Shared Access Signature (SAS) token URL.\n2. Attempt to access the storage resource (e.g., blob, container) using the provided URL with the SAS token in a web browser or storage explorer.\n3. Verify successful access and the allowed operations (read, write, delete).",
    "remediation": "Immediately revoke the exposed Azure SAS token (if it's a service SAS or account SAS) or regenerate the associated storage account key to invalidate all SAS tokens generated with it. Review storage activity for unauthorized operations."
  },
  "AzureSearchAdminKey": {
    "service": "Azure Search",
    "category": "Cloud Provider (Search)",
    "impact": "Administrative control over Azure Search services, allowing an attacker to manage search indexes, data sources, and query keys, potentially leading to data tampering, injection of malicious content into search results, or denial of service for search functionalities.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure Search Admin Key.\n2. Attempt to list search indexes or create a new index via the Azure Search REST API with the found key.\n3. Verify successful administrative action.",
    "remediation": "Immediately rotate the Azure Search Admin Key and regenerate the key. Review Azure Monitor logs for any unauthorized activity."
  },
  "AzureSearchQueryKey": {
    "service": "Azure Search",
    "category": "Cloud Provider (Search)",
    "impact": "Unauthorized access to query search indexes and retrieve data from Azure Search service, potentially leading to data exfiltration or reconnaissance of indexed information.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Azure Search Query Key.\n2. Use the key to query a search index via the Azure Search REST API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Azure Search Query Key immediately. Note that this key is designed for client-side use, but should still be kept confidential to prevent abuse."
  },
  "AzureStorage": {
    "service": "Azure Storage",
    "category": "Cloud Provider (Storage)",
    "impact": "Complete control over Azure Storage accounts, including blobs, files, queues, and tables, allowing for data theft, deletion, modification, or injection of malicious content, leading to severe data integrity and availability risks.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Azure Storage Account key.\n2. Configure Azure CLI/Storage Explorer with the found key.\n3. Attempt to list or manage storage containers/blobs.\n4. Verify successful access and data manipulation.",
    "remediation": "Immediately rotate the Azure Storage Account keys and review Azure Monitor logs for unauthorized access."
  },
  "Bannerbear": {
    "service": "Bannerbear",
    "category": "Image & Video Generation",
    "impact": "Unauthorized access to and manipulation of dynamic image, video, and GIF generation, potentially leading to the creation of malicious content, brand impersonation, or excessive API usage charges.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Bannerbear API key.\n2. Attempt to generate an image or video using the Bannerbear API with the found key.\n3. Verify successful generation.",
    "remediation": "Revoke and regenerate the Bannerbear API key immediately."
  },
  "Baremetrics": {
    "service": "Baremetrics",
    "category": "Subscription Analytics",
    "impact": "Unauthorized access to and analysis of sensitive subscription data, potentially leading to exposure of revenue metrics, customer churn rates, or other proprietary business insights.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Baremetrics API key.\n2. Attempt to retrieve subscription data or metrics using the Baremetrics API with the found key.\n3. Verify successful data retrieval.",
    "remediation": "Revoke and regenerate the Baremetrics API key immediately."
  },
  "Beamer": {
    "service": "Beamer",
    "category": "User Engagement",
    "impact": "Unauthorized access to and management of user engagement information, potentially leading to unauthorized product updates, misleading communication, or exposure of user feedback.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Beamer API key.\n2. Attempt to list or create product updates/notifications using the Beamer API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Beamer API key immediately."
  },
  "Beebole": {
    "service": "Beebole",
    "category": "Time Tracking & Business Management",
    "impact": "Unauthorized access to and management of time tracking data and other business-related information, potentially leading to inaccurate billing, project overruns, or exposure of sensitive employee data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Beebole API key.\n2. Attempt to list or modify time entries or project data using the Beebole API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Beebole API key immediately."
  },
  "Besnappy": {
    "service": "Besnappy",
    "category": "Customer Service",
    "impact": "Unauthorized access to customer service data, potentially exposing sensitive customer interactions, support tickets, or personal information, leading to privacy breaches or reputational damage.",
    "severity": "High",
    "poc_template": "1. Locate exposed Besnappy API key.\n2. Attempt to retrieve customer service tickets or customer data using the Besnappy API with the found key.\n3. Verify successful data retrieval.",
    "remediation": "Revoke the exposed Besnappy API key and generate a new one immediately."
  },
  "Besttime": {
    "service": "Besttime",
    "category": "Location Data",
    "impact": "Unauthorized access to and utilization of services that predict optimal visitation times for locations, potentially leading to excessive API usage charges or exploitation of location-based insights.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Besttime API key.\n2. Use the key to query the best time to visit a location via the Besttime API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Besttime API key immediately."
  },
  "BetterStack": {
    "service": "Betterstack",
    "category": "Monitoring & Uptime",
    "impact": "Unauthorized access to and management of website and API monitoring services, potentially leading to disabling alerts, altering uptime checks, or exposing sensitive performance data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Betterstack API key.\n2. Attempt to list or modify uptime monitors via the Betterstack API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Betterstack API key immediately."
  },
  "Billomat": {
    "service": "Billomat",
    "category": "Invoicing Software",
    "impact": "Unauthorized access to and management of invoices, clients, and other related financial data, potentially leading to financial fraud, data manipulation, or exposure of sensitive billing information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Billomat API key.\n2. Attempt to retrieve or modify invoice data or client information using the Billomat API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Billomat API key immediately."
  },
  "BingSubscriptionKey": {
    "service": "Bing Web Search API",
    "category": "Search Engine",
    "impact": "Unauthorized access to and utilization of Bing Web Search API, potentially leading to excessive API usage charges or the scraping of search results for unintended purposes.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Bing Subscription Key.\n2. Use the key to perform a web search via the Bing Web Search API.\n3. Verify successful search result retrieval.",
    "remediation": "Rotate the Bing Subscription Key immediately."
  },
  "BitLyAccessToken": {
    "service": "Bitly",
    "category": "URL Shortening",
    "impact": "Unauthorized interaction with the Bitly API, allowing for the creation, management, and tracking of shortened URLs. This could lead to the creation of malicious shortened URLs (e.g., for phishing), tracking of private links, or disruption of existing short links.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Bitly access token.\n2. Attempt to create a new shortened URL or retrieve analytics for an existing one using the Bitly API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the Bitly access token immediately and generate a new one."
  },
  "Bitbar": {
    "service": "Bitbar",
    "category": "Mobile App Testing",
    "impact": "Unauthorized access to and management of mobile app testing resources and data, potentially leading to the injection of malicious test cases, exposure of test results, or disruption of testing pipelines.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Bitbar API key.\n2. Attempt to list or initiate a mobile app test using the Bitbar API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Bitbar API key immediately."
  },
  "BitcoinAverage": {
    "service": "BitcoinAverage",
    "category": "Cryptocurrency Data",
    "impact": "Unauthorized access to cryptocurrency market data, potentially leading to data scraping or misuse of market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed BitcoinAverage API key.\n2. Use the key to fetch cryptocurrency market data via the BitcoinAverage API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the BitcoinAverage API key immediately."
  },
  "Bitfinex": {
    "service": "Bitfinex",
    "category": "Cryptocurrency Exchange",
    "impact": "Unauthorized access to and management of cryptocurrency trading accounts, potentially leading to unauthorized trades, fund manipulation, or exposure of sensitive trading history.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Bitfinex API key.\n2. Attempt to retrieve account balance or initiate a trade using the Bitfinex API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Bitfinex API key immediately and enable appropriate security measures like IP whitelisting."
  },
  "Bitmex": {
    "service": "Bitmex",
    "category": "Cryptocurrency Exchange & Derivatives",
    "impact": "Unauthorized access to and programmatic trading on the Bitmex platform, potentially leading to unauthorized trades, fund manipulation, or exposure of sensitive trading history.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Bitmex API key.\n2. Attempt to retrieve account balance or place an order using the Bitmex API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Bitmex API key immediately and enable appropriate security measures like IP whitelisting."
  },
  "Blazemeter": {
    "service": "Blazemeter",
    "category": "Continuous Testing",
    "impact": "Unauthorized access to and management of performance tests and other testing resources, potentially leading to the injection of malicious tests, exposure of test results, or disruption of testing pipelines.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Blazemeter keys.\n2. Attempt to list or initiate a performance test using the Blazemeter API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Blazemeter keys immediately."
  },
  "BlitApp": {
    "service": "BlitApp",
    "category": "Application Management",
    "impact": "Unauthorized access to and modification of application data, potentially leading to application misconfiguration, data tampering, or service disruption.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed BlitApp API key.\n2. Attempt to list or modify application data using the BlitApp API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the BlitApp API key immediately."
  },
  "Blogger": {
    "service": "Blogger",
    "category": "Blogging Platform",
    "impact": "Unauthorized access to and management of blogs, potentially leading to unauthorized content publishing, content modification, or deletion of blog posts.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Blogger API key.\n2. Attempt to list or modify blog posts using the Blogger API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Blogger API key immediately."
  },
  "BombBomb": {
    "service": "BombBomb",
    "category": "Video Messaging",
    "impact": "Unauthorized access to and management of video email campaigns and contacts, potentially leading to unauthorized video sending, spamming, or exposure of contact lists.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed BombBomb API key.\n2. Attempt to list or send a test video email using the BombBomb API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the BombBomb API key immediately."
  },
  "BoostNote": {
    "service": "BoostNote",
    "category": "Note-taking Application",
    "impact": "Unauthorized access to note-taking application services, potentially leading to data exfiltration of sensitive notes or unauthorized modification of content.",
    "severity": "High",
    "poc_template": "1. Locate exposed BoostNote secret (API key/token).\n2. Attempt to access or modify notes using the BoostNote API with the found secret.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke the exposed BoostNote secret and generate a new one immediately."
  },
  "Borgbase": {
    "service": "Borgbase",
    "category": "Backup Hosting",
    "impact": "Unauthorized access to and management of Borg repositories, potentially leading to backup data theft, deletion, or corruption, severely impacting data recovery capabilities.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Borgbase API key.\n2. Attempt to list or modify Borg repositories using the Borgbase API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Borgbase API key immediately."
  },
  "Box": {
    "service": "Box",
    "category": "Cloud Storage & Collaboration",
    "impact": "Unauthorized access to and manipulation of files and folders in Box, potentially leading to data theft, deletion, or unauthorized collaboration.",
    "severity": "High",
    "poc_template": "1. Locate exposed Box token.\n2. Attempt to list files or download content from a Box account using the Box API with the found token.\n3. Verify successful data access.",
    "remediation": "Revoke the exposed Box token immediately and generate a new one if necessary."
  },
  "BoxOauth": {
    "service": "Box",
    "category": "Cloud Storage & Collaboration",
    "impact": "Unauthorized access to and manipulation of files and folders in Box on behalf of a user, potentially leading to data theft, deletion, or unauthorized collaboration.",
    "severity": "High",
    "poc_template": "1. Locate exposed Box OAuth credentials.\n2. Attempt to list files or download content from a Box account using the Box API with the found OAuth token on behalf of the authorized user.\n3. Verify successful data access.",
    "remediation": "Revoke the Box OAuth token immediately and re-authorize the application if necessary."
  },
  "BraintreePayments": {
    "service": "Braintree Payments",
    "category": "Payment Gateway",
    "impact": "Unauthorized processing of payments, management of customer data, and other payment-related operations, potentially leading to financial fraud, theft of payment information, or chargeback issues.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Braintree API keys.\n2. Attempt to make a test transaction or retrieve customer data using the Braintree API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke and regenerate the Braintree API keys. Review all transaction logs for unauthorized activity."
  },
  "Brandfetch": {
    "service": "Brandfetch",
    "category": "Brand Data",
    "impact": "Unauthorized access to brand data including logos, colors, and fonts, potentially leading to data scraping or misuse of proprietary brand assets.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Brandfetch API key.\n2. Use the key to fetch brand data for a known company via the Brandfetch API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Brandfetch API key immediately."
  },
  "BrowserStack": {
    "service": "BrowserStack",
    "category": "Cloud Testing",
    "impact": "Unauthorized access to and management of cloud web and mobile testing environments, potentially leading to the injection of malicious tests, exposure of test results, or resource abuse.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed BrowserStack credentials.\n2. Attempt to list or initiate a test session using the BrowserStack API with the found credentials.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate BrowserStack credentials immediately."
  },
  "Browshot": {
    "service": "Browshot",
    "category": "Screenshot Service",
    "impact": "Unauthorized automation and management of webpage screenshots, potentially leading to excessive API usage charges or the capture of sensitive internal web pages.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Browshot API key.\n2. Use the key to generate a screenshot of a public webpage via the Browshot API.\n3. Verify successful screenshot generation.",
    "remediation": "Rotate the Browshot API key immediately."
  },
  "BscScan": {
    "service": "BscScan",
    "category": "Blockchain Explorer",
    "impact": "Unauthorized access to data from the Binance Smart Chain blockchain, potentially leading to excessive API usage charges or the scraping of transactional data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed BscScan API key.\n2. Use the key to query blockchain data (e.g., transaction history for an address) via the BscScan API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the BscScan API key immediately."
  },
  "BuddyNS": {
    "service": "BuddyNS",
    "category": "DNS Hosting",
    "impact": "Unauthorized management of DNS zones and records, potentially leading to DNS hijacking, redirection of traffic, or denial of service for hosted domains.",
    "severity": "High",
    "poc_template": "1. Locate exposed BuddyNS API key.\n2. Attempt to list or modify DNS records for a zone using the BuddyNS API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the BuddyNS API key immediately."
  },
  "Budibase": {
    "service": "Budibase",
    "category": "Low-Code Platform",
    "impact": "Unauthorized access to and modification of applications and data within the Budibase platform, potentially leading to data breaches, application manipulation, or disruption of internal tools.",
    "severity": "High",
    "poc_template": "1. Locate exposed Budibase API key.\n2. Attempt to list or modify applications/data using the Budibase API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Budibase API key immediately."
  },
  "Bugherd": {
    "service": "Bugherd",
    "category": "Feedback & Bug Tracking",
    "impact": "Unauthorized access to and management of projects, tasks, and feedback data, potentially leading to exposure of sensitive project issues, manipulation of bug reports, or disruption of development workflows.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Bugherd API key.\n2. Attempt to list or create a bug report/task using the Bugherd API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Bugherd API key immediately."
  },
  "Bugsnag": {
    "service": "Bugsnag",
    "category": "Error Monitoring",
    "impact": "Unauthorized reporting and management of errors in web and mobile applications, potentially leading to the injection of false error reports, consumption of API quotas, or exposure of sensitive application issues.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Bugsnag API key.\n2. Attempt to send a test error report to Bugsnag using the found key.\n3. Verify the error appears in the Bugsnag dashboard (if accessible).",
    "remediation": "Rotate the Bugsnag API key immediately."
  },
  "Buildkite": {
    "service": "Buildkite",
    "category": "CI/CD Platform",
    "impact": "Unauthorized interaction with Buildkite API, allowing for the management of continuous integration and delivery pipelines, potentially leading to unauthorized code deployments, access to build artifacts, or disruption of CI/CD workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Buildkite access token.\n2. Attempt to list pipelines or trigger a build using the Buildkite API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the Buildkite access token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Bulbul": {
    "service": "Bulbul",
    "category": "API Service",
    "impact": "Unauthorized access to and modification of data within the Bulbul API service, potentially leading to data breaches, data manipulation, or service disruption, depending on the service's functionality.",
    "severity": "High",
    "poc_template": "1. Locate exposed Bulbul API key.\n2. Attempt to access or modify data using the Bulbul API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Bulbul API key immediately."
  },
  "Bulksms": {
    "service": "BulkSMS",
    "category": "SMS Gateway",
    "impact": "Unauthorized sending of SMS messages in bulk, potentially leading to spamming, phishing attempts, or significant financial cost due to message charges.",
    "severity": "High",
    "poc_template": "1. Locate exposed BulkSMS credentials.\n2. Attempt to send a test SMS message using the BulkSMS API with the found credentials.\n3. Verify successful message delivery.",
    "remediation": "Revoke and regenerate the BulkSMS credentials immediately."
  },
  "ButterCMS": {
    "service": "ButterCMS",
    "category": "Headless CMS",
    "impact": "Unauthorized access to and modification of content stored in ButterCMS, potentially leading to unauthorized content publishing, content manipulation, or deletion of website/application content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ButterCMS API key.\n2. Attempt to retrieve or modify content via the ButterCMS API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the ButterCMS API key immediately."
  },
  "Caflou": {
    "service": "Caflou",
    "category": "Business Management Software",
    "impact": "Unauthorized access to and modification of project, task, and financial data, potentially leading to project disruption, financial fraud, or exposure of sensitive business information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Caflou API key.\n2. Attempt to retrieve or modify project data or financial records using the Caflou API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Caflou API key immediately."
  },
  "Calendarific": {
    "service": "Calendarific",
    "category": "Holiday Data",
    "impact": "Unauthorized access to holiday information, potentially leading to excessive API usage charges or data scraping of holiday schedules.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Calendarific API key.\n2. Use the key to fetch holiday data for a specific country/year via the Calendarific API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Calendarific API key immediately."
  },
  "CalendlyApiKey": {
    "service": "Calendly",
    "category": "Online Scheduling",
    "impact": "Unauthorized access to and management of Calendly accounts and data, potentially leading to appointment manipulation, exposure of sensitive meeting details, or disruption of scheduling services.",
    "severity": "High",
    "poc_template": "1. Locate exposed Calendly API key.\n2. Attempt to list or modify appointments using the Calendly API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Calendly API key immediately."
  },
  "CalorieNinja": {
    "service": "CalorieNinja",
    "category": "Nutritional Data",
    "impact": "Unauthorized access to nutritional information for various foods, potentially leading to data scraping or misuse of dietary data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed CalorieNinja API key.\n2. Use the key to query nutritional data for a food item via the CalorieNinja API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the CalorieNinja API key immediately."
  },
  "Campayn": {
    "service": "Campayn",
    "category": "Email Marketing",
    "impact": "Unauthorized access to and management of email lists, campaigns, and tracking performance, potentially leading to unauthorized email sending, spamming, or exposure of sensitive subscriber data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Campayn API key.\n2. Attempt to list email lists or send a test email campaign using the Campayn API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Campayn API key immediately."
  },
  "CannyIo": {
    "service": "Canny",
    "category": "User Feedback",
    "impact": "Unauthorized access to and management of user feedback boards and related data, potentially leading to the injection of false feedback, manipulation of feature requests, or exposure of product development insights.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Canny API key.\n2. Attempt to list or create a feedback post using the Canny API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Canny API key immediately."
  },
  "CapsuleCRM": {
    "service": "CapsuleCRM",
    "category": "Customer Relationship Management (CRM)",
    "impact": "Unauthorized access to and management of customer data and interactions, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "High",
    "poc_template": "1. Locate exposed CapsuleCRM API key.\n2. Attempt to list or modify customer records using the CapsuleCRM API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the CapsuleCRM API key immediately."
  },
  "CaptainData": {
    "service": "CaptainData",
    "category": "Data Extraction & Processing",
    "impact": "Unauthorized access to and control over data extraction and processing automation, potentially leading to data exfiltration, resource abuse, or execution of malicious data operations.",
    "severity": "High",
    "poc_template": "1. Locate exposed CaptainData API key.\n2. Attempt to list or run a data extraction workflow using the CaptainData API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the CaptainData API key immediately."
  },
  "CarbonInterface": {
    "service": "CarbonInterface",
    "category": "Carbon Emissions API",
    "impact": "Unauthorized utilization of carbon emissions estimation services, potentially leading to excessive API usage charges or the generation of misleading environmental data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed CarbonInterface API key.\n2. Use the key to estimate carbon emissions for an activity via the CarbonInterface API.\n3. Verify successful estimation.",
    "remediation": "Rotate the CarbonInterface API key immediately."
  },
  "Cashboard": {
    "service": "Cashboard",
    "category": "Financial Management",
    "impact": "Unauthorized access to and management of financial data and accounts, potentially leading to financial fraud, data manipulation, or exposure of sensitive financial records.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Cashboard credentials.\n2. Attempt to access or modify financial data (e.g., invoices, expenses) using the Cashboard API.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate Cashboard credentials immediately."
  },
  "Caspio": {
    "service": "Caspio",
    "category": "Cloud Database Platform",
    "impact": "Unauthorized access to and management of custom database applications, potentially leading to data breaches, application manipulation, or unauthorized data exposure.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Caspio credentials.\n2. Attempt to access or modify data within a Caspio database application using the Caspio API.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke and regenerate Caspio credentials immediately."
  },
  "Censys": {
    "service": "Censys",
    "category": "Internet Search Engine",
    "impact": "Unauthorized access to and querying of Internet host and network data, potentially leading to reconnaissance of public-facing infrastructure, data scraping, or misuse of security intelligence.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Censys API key.\n2. Use the key to query for host or network information via the Censys API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Censys API key immediately."
  },
  "CentralStationCRM": {
    "service": "CentralStationCRM",
    "category": "Customer Relationship Management (CRM)",
    "impact": "Unauthorized access to and management of customer data, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "High",
    "poc_template": "1. Locate exposed CentralStationCRM API key.\n2. Attempt to list or modify customer records using the CentralStationCRM API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the CentralStationCRM API key immediately."
  },
  "CexIO": {
    "service": "CexIO",
    "category": "Cryptocurrency Exchange",
    "impact": "Unauthorized access to and management of cryptocurrency accounts and transactions, potentially leading to unauthorized trades, fund manipulation, or exposure of sensitive trading history.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed CexIO API key.\n2. Attempt to retrieve account balance or initiate a trade using the CexIO API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the CexIO API key immediately and enable appropriate security measures like IP whitelisting."
  },
  "Chartmogul": {
    "service": "ChartMogul",
    "category": "Subscription Analytics",
    "impact": "Unauthorized access to and management of sensitive subscription data, potentially leading to exposure of revenue metrics, customer churn rates, or other proprietary business insights.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ChartMogul API key.\n2. Attempt to retrieve subscription data or metrics using the ChartMogul API with the found key.\n3. Verify successful data retrieval.",
    "remediation": "Revoke and regenerate the ChartMogul API key immediately."
  },
  "Chatbot": {
    "service": "Chatbot",
    "category": "Chatbot Platform",
    "impact": "Unauthorized access to create, modify, and retrieve chatbot stories and resources, potentially leading to the injection of malicious dialogue, impersonation of the chatbot, or exposure of sensitive conversation flows.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Chatbot API key.\n2. Attempt to list or create a chatbot story using the Chatbot API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Chatbot API key immediately."
  },
  "Chatfule": {
    "service": "Chatfuel",
    "category": "Chatbot Platform",
    "impact": "Unauthorized access to and management of chatbot configurations and interactions, potentially leading to the injection of malicious dialogue, impersonation of the chatbot, or exposure of sensitive conversation flows.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Chatfuel API key.\n2. Attempt to list or modify chatbot configurations using the Chatfuel API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Chatfuel API key immediately."
  },
  "ChecIO": {
    "service": "ChecIO",
    "category": "E-commerce Platform",
    "impact": "Unauthorized access to and management of products, carts, and orders on an e-commerce platform, potentially leading to order manipulation, financial fraud, or customer data theft.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed ChecIO API key.\n2. Attempt to list products or create a test order using the ChecIO API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the ChecIO API key immediately."
  },
  "ChecklyHQ": {
    "service": "ChecklyHQ",
    "category": "Monitoring Service",
    "impact": "Unauthorized access to and management of API and browser checks, potentially leading to disabling monitoring, altering alerts, or exposing sensitive application performance data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ChecklyHQ API key.\n2. Attempt to list or modify API/browser checks using the ChecklyHQ API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the ChecklyHQ API key immediately."
  },
  "Checkout": {
    "service": "Checkout",
    "category": "Payment Solution Provider",
    "impact": "Unauthorized processing of payments and management of customer data, potentially leading to financial fraud, theft of payment information, or chargeback issues.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Checkout API keys.\n2. Attempt to make a test transaction or retrieve customer data using the Checkout API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke and regenerate the Checkout API keys. Review all transaction logs for unauthorized activity."
  },
  "Checkvist": {
    "service": "Checkvist",
    "category": "Task Management",
    "impact": "Unauthorized access to and management of tasks and data, potentially leading to the manipulation of project tasks, exposure of sensitive to-do lists, or disruption of workflow.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Checkvist credentials.\n2. Attempt to list or modify tasks using the Checkvist API with the found credentials.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Checkvist credentials and generate new ones immediately."
  },
  "Cicero": {
    "service": "Cicero",
    "category": "Geospatial & Civic Data",
    "impact": "Unauthorized access to various geospatial and civic data APIs, potentially leading to excessive API usage charges or data scraping of sensitive location-based information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Cicero key.\n2. Use the key to query civic or geospatial data via the Cicero API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Cicero key immediately."
  },
  "Circle": {
    "service": "CircleCI",
    "category": "CI/CD Platform",
    "impact": "Unauthorized interaction with the CircleCI API, allowing for the management of continuous integration and delivery pipelines, potentially leading to unauthorized code deployments, access to build artifacts, or disruption of CI/CD workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed CircleCI token.\n2. Attempt to list pipelines or trigger a build using the CircleCI API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the CircleCI token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Clarifai": {
    "service": "Clarifai",
    "category": "AI Platform (Visual Recognition)",
    "impact": "Unauthorized access to and management of visual recognition models and data, potentially leading to resource abuse, exposure of image/video analysis results, or the training of unauthorized models.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Clarifai API key.\n2. Attempt to analyze an image or list models using the Clarifai API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Clarifai API key immediately."
  },
  "Clearbit": {
    "service": "Clearbit",
    "category": "Data Enrichment",
    "impact": "Unauthorized access to and retrieval of detailed information about companies and people, potentially leading to data scraping, competitive intelligence gathering, or privacy breaches.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Clearbit API key.\n2. Use the key to enrich data for an email address or company domain via the Clearbit API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Clearbit API key immediately."
  },
  "ClickHelp": {
    "service": "ClickHelp",
    "category": "Documentation Tool",
    "impact": "Unauthorized access to and modification of online documentation data, potentially leading to unauthorized content publishing, content manipulation, or deletion of crucial documentation.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ClickHelp API key.\n2. Attempt to list or modify documentation articles using the ClickHelp API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the ClickHelp API key immediately."
  },
  "ClickSendsms": {
    "service": "ClickSend",
    "category": "Business Communication",
    "impact": "Unauthorized access to and management of SMS, email, and voice communication services, potentially leading to unauthorized messaging, spamming, or significant financial cost due to message charges.",
    "severity": "High",
    "poc_template": "1. Locate exposed ClickSend API key.\n2. Attempt to send a test SMS message using the ClickSend API with the found key.\n3. Verify successful message delivery.",
    "remediation": "Revoke and regenerate the ClickSend API key immediately."
  },
  "ClickupPersonalToken": {
    "service": "ClickUp",
    "category": "Project Management",
    "impact": "Unauthorized access to and modification of project management data (tasks, lists, spaces) on behalf of a user, potentially leading to project disruption, data exfiltration, or unauthorized task assignments.",
    "severity": "High",
    "poc_template": "1. Locate exposed ClickUp Personal Token.\n2. Attempt to list or modify tasks/projects using the ClickUp API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the ClickUp Personal Token immediately and generate a new one, storing it securely."
  },
  "Cliengo": {
    "service": "Cliengo",
    "category": "Chatbot Service",
    "impact": "Unauthorized access to and management of chatbot configurations and data, potentially leading to the injection of malicious dialogue, impersonation of the chatbot, or exposure of lead generation interactions.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Cliengo API key.\n2. Attempt to list or modify chatbot configurations or leads using the Cliengo API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Cliengo API key immediately."
  },
  "Clinchpad": {
    "service": "Clinchpad",
    "category": "CRM Tool",
    "impact": "Unauthorized access to and modification of CRM data, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "High",
    "poc_template": "1. Locate exposed Clinchpad API key.\n2. Attempt to list or modify customer records using the Clinchpad API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Clinchpad API key immediately."
  },
  "Clockify": {
    "service": "Clockify",
    "category": "Time Tracking",
    "impact": "Unauthorized access to and modification of time tracking data, potentially leading to inaccurate billing, project overruns, or exposure of sensitive employee work hours.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Clockify API key.\n2. Attempt to list or modify time entries using the Clockify API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Clockify API key immediately."
  },
  "ClockworkSMS": {
    "service": "Clockwork SMS",
    "category": "SMS Gateway",
    "impact": "Unauthorized sending of SMS messages, potentially leading to spamming, phishing attempts, or significant financial cost due to message charges.",
    "severity": "High",
    "poc_template": "1. Locate exposed Clockwork SMS user key/access token.\n2. Attempt to send a test SMS message using the Clockwork SMS API with the found credentials.\n3. Verify successful message delivery.",
    "remediation": "Revoke the exposed Clockwork SMS credentials and generate new ones immediately."
  },
  "Close": {
    "service": "Close",
    "category": "CRM Software",
    "impact": "Unauthorized access to and manipulation of CRM data, including customer relationships and sales leads, potentially leading to data breaches, lead theft, or disruption of sales operations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Close API key.\n2. Attempt to retrieve or modify CRM data (e.g., leads, contacts) using the Close API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Close API key immediately."
  },
  "CloudConvert": {
    "service": "CloudConvert",
    "category": "File Conversion",
    "impact": "Unauthorized access to and management of file conversion operations, potentially leading to resource abuse, unauthorized file conversions, or exposure of converted file content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed CloudConvert API key.\n2. Attempt to initiate a file conversion or check conversion status using the CloudConvert API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the CloudConvert API key immediately."
  },
  "CloudElements": {
    "service": "CloudElements",
    "category": "API Integration Platform",
    "impact": "Unauthorized access to and management of API integrations, potentially leading to data breaches, service disruptions, or unauthorized actions across various cloud services connected to the platform.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed CloudElements credentials.\n2. Attempt to list or manage integrations or connected services via the CloudElements API.\n3. Verify successful administrative access.",
    "remediation": "Revoke and regenerate CloudElements credentials immediately. Review all audit logs for unauthorized activities."
  },
  "CloudImage": {
    "service": "CloudImage",
    "category": "Image Optimization & Delivery",
    "impact": "Unauthorized access to and modification of image data, potentially leading to image manipulation, unauthorized image delivery, or disruption of content presentation.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed CloudImage API key.\n2. Attempt to optimize or transform an image using the CloudImage API with the found key.\n3. Verify successful image processing.",
    "remediation": "Rotate the CloudImage API key immediately."
  },
  "CloudflareApiToken": {
    "service": "Cloudflare",
    "category": "Web Infrastructure & Security",
    "impact": "Unauthorized management and interaction with Cloudflare services, potentially leading to DNS manipulation, routing changes, WAF rule alterations, or exposure of website traffic, severely impacting website security and availability.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Cloudflare API token.\n2. Attempt to list DNS records, manage WAF rules, or purge cache for a zone using the Cloudflare API with the found token.\n3. Verify successful administrative action.",
    "remediation": "Immediately revoke the exposed Cloudflare API token and generate a new one with restricted permissions if possible. Review Cloudflare audit logs for any unauthorized changes."
  },
  "CloudflareCaKey": {
    "service": "Cloudflare",
    "category": "Web Infrastructure & Security",
    "impact": "Unauthorized management of SSL/TLS certificates and other security settings, potentially leading to the issuance of fraudulent certificates, compromising encrypted communications, or weakening website security.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Cloudflare CA key.\n2. Attempt to manage or issue SSL/TLS certificates through Cloudflare using the found key.\n3. Verify successful interaction with certificate management.",
    "remediation": "Immediately revoke the exposed Cloudflare CA key and generate a new one. Review Cloudflare audit logs for any unauthorized certificate activities."
  },
  "CloudflareGlobalApiKey": {
    "service": "Cloudflare",
    "category": "Web Infrastructure & Security",
    "impact": "Complete administrative control over all Cloudflare services associated with the account, including content delivery, DDoS mitigation, DNS, and security settings, leading to potential website hijacking, data redirection, or severe service disruption.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Cloudflare Global API Key.\n2. Attempt to list all zones, change DNS records, or modify security settings for any zone using the Cloudflare API with the found key.\n3. Verify successful administrative control.",
    "remediation": "Immediately revoke the exposed Cloudflare Global API Key and generate a new one. Restrict access to this key and consider using API tokens with specific permissions instead. Review Cloudflare audit logs for any unauthorized changes."
  },
  "Cloudmersive": {
    "service": "Cloudmersive",
    "category": "API Suite (Validation, Conversion, Security)",
    "impact": "Unauthorized access to various data validation, conversion, and security APIs, potentially leading to excessive API usage charges, misuse of data processing capabilities, or bypassing security checks.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Cloudmersive API key.\n2. Attempt to perform a data validation or file conversion operation via a Cloudmersive API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Cloudmersive API key immediately."
  },
  "Cloudplan": {
    "service": "Cloudplan",
    "category": "Cloud Business Solutions",
    "impact": "Unauthorized access to and management of user sessions and data within cloud-based business solutions, potentially leading to session hijacking, data breaches, or unauthorized access to sensitive business information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Cloudplan session ID.\n2. Attempt to authenticate or access user data within Cloudplan using the found session ID.\n3. Verify successful session takeover or data access.",
    "remediation": "Invalidate the exposed Cloudplan session ID and ensure secure session management practices are in place."
  },
  "Cloudsmith": {
    "service": "Cloudsmith",
    "category": "Package Management",
    "impact": "Unauthorized management and distribution of packages, potentially leading to the injection of malicious packages, deletion of legitimate packages, or disruption of software delivery pipelines.",
    "severity": "High",
    "poc_template": "1. Locate exposed Cloudsmith API key.\n2. Attempt to list or publish a package to a repository using the Cloudsmith API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Cloudsmith API key immediately."
  },
  "Cloverly": {
    "service": "Cloverly",
    "category": "Carbon Offsetting",
    "impact": "Unauthorized access to and management of carbon offsetting services, potentially leading to fraudulent offsetting claims or resource abuse.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Cloverly API key.\n2. Attempt to estimate or initiate a carbon offset via the Cloverly API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Cloverly API key immediately."
  },
  "Cloze": {
    "service": "Cloze",
    "category": "Relationship Management",
    "impact": "Unauthorized access to and management of user data and interactions, potentially leading to exposure of sensitive relationship details, contact information, or communication history.",
    "severity": "High",
    "poc_template": "1. Locate exposed Cloze API key.\n2. Attempt to retrieve or modify contact data or interaction logs using the Cloze API with the found key.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke and regenerate the Cloze API key immediately."
  },
  "ClustDoc": {
    "service": "ClustDoc",
    "category": "Document Management",
    "impact": "Unauthorized access to and management of documents and workflows, potentially leading to data theft, document manipulation, or disruption of document-based processes.",
    "severity": "High",
    "poc_template": "1. Locate exposed ClustDoc API key.\n2. Attempt to list or modify documents/workflows using the ClustDoc API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the ClustDoc API key immediately."
  },
  "Coda": {
    "service": "Coda",
    "category": "Collaborative Documents & Applications",
    "impact": "Unauthorized access to and manipulation of data within Coda documents and applications, potentially leading to data theft, data corruption, or exposure of sensitive collaborative content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Coda API key.\n2. Attempt to list or modify rows/tables in a Coda document using the Coda API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Coda API key immediately."
  },
  "Codacy": {
    "service": "Codacy",
    "category": "Code Review & Quality",
    "impact": "Unauthorized access to and management of code quality reports and settings, potentially leading to the injection of false code analysis results, disabling of quality checks, or exposure of sensitive code vulnerabilities.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Codacy API token.\n2. Attempt to list repositories or retrieve code quality reports using the Codacy API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Codacy API token immediately."
  },
  "Codeclimate": {
    "service": "Codeclimate",
    "category": "Code Review & Analysis",
    "impact": "Unauthorized access to and management of repositories and their analysis results, potentially leading to exposure of code vulnerabilities, manipulation of code quality metrics, or disruption of code analysis workflows.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Codeclimate token.\n2. Attempt to list repositories or retrieve analysis results using the Codeclimate API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Codeclimate token and generate a new one immediately."
  },
  "Codemagic": {
    "service": "Codemagic",
    "category": "CI/CD Platform (Mobile Apps)",
    "impact": "Unauthorized automation and management of mobile application build and deployment processes, potentially leading to unauthorized app releases, injection of malicious code into builds, or disruption of CI/CD pipelines.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Codemagic API key.\n2. Attempt to list or trigger a mobile app build using the Codemagic API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Codemagic API key immediately."
  },
  "Codequiry": {
    "service": "Codequiry",
    "category": "Plagiarism Detection",
    "impact": "Unauthorized utilization of plagiarism detection features, potentially leading to excessive API usage charges or the unauthorized submission/checking of content.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Codequiry API key.\n2. Attempt to submit content for plagiarism detection using the Codequiry API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Codequiry API key immediately."
  },
  "CoinApi": {
    "service": "CoinApi",
    "category": "Cryptocurrency Market Data",
    "impact": "Unauthorized access to real-time and historical cryptocurrency market data, potentially leading to data scraping or misuse of market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed CoinApi key.\n2. Use the key to fetch real-time cryptocurrency data via the CoinApi.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the CoinApi key immediately."
  },
  "Coinbase": {
    "service": "Coinbase",
    "category": "Digital Currency Exchange",
    "impact": "Unauthorized access to and management of a user's Coinbase account and transactions, potentially leading to unauthorized cryptocurrency trades, fund transfers, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Coinbase API key.\n2. Attempt to retrieve account balance or initiate a transaction using the Coinbase API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Coinbase API key immediately and enable appropriate security measures like IP whitelisting."
  },
  "CoinbaseWaaSCoinbase": {
    "service": "Coinbase WaaS (Wallet as a Service)",
    "category": "Cryptocurrency Wallet Management",
    "impact": "Unauthorized access to and management of cryptocurrency wallets, potentially leading to unauthorized transactions, fund theft, or exposure of sensitive wallet information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Coinbase WaaS API key.\n2. Attempt to create or manage a cryptocurrency wallet using the Coinbase WaaS API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Coinbase WaaS API key immediately and enable appropriate security measures like IP whitelisting."
  },
  "Coinlayer": {
    "service": "Coinlayer",
    "category": "Cryptocurrency Exchange Rates",
    "impact": "Unauthorized access to real-time and historical cryptocurrency exchange rates, potentially leading to excessive API usage charges or data scraping of market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Coinlayer API key.\n2. Use the key to fetch cryptocurrency exchange rates via the Coinlayer API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Coinlayer API key immediately."
  },
  "Coinlib": {
    "service": "Coinlib",
    "category": "Cryptocurrency Data",
    "impact": "Unauthorized access to cryptocurrency data, potentially leading to data scraping or misuse of market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Coinlib API key.\n2. Use the key to fetch cryptocurrency data via the Coinlib API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Coinlib API key immediately."
  },
  "Collect2": {
    "service": "Collect2",
    "category": "Data Collection & Management",
    "impact": "Unauthorized creation, reading, updating, and deletion of data via webhooks, potentially leading to data exfiltration, data corruption, or injection of malicious data into connected systems.",
    "severity": "High",
    "poc_template": "1. Locate exposed Collect2 API key.\n2. Attempt to create, read, update, or delete data using the Collect2 API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Collect2 API key immediately."
  },
  "Column": {
    "service": "Column",
    "category": "Entity Data Management",
    "impact": "Unauthorized access to and modification of entity data, potentially leading to data breaches, data manipulation, or disruption of data integrity.",
    "severity": "High",
    "poc_template": "1. Locate exposed Column key.\n2. Attempt to list or modify entity data using the Column API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Column key immediately."
  },
  "CommerceJS": {
    "service": "CommerceJS",
    "category": "Headless E-commerce",
    "impact": "Unauthorized access to and management of e-commerce functionalities, including products, carts, and orders, potentially leading to financial fraud, customer data theft, or disruption of online store operations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed CommerceJS API key.\n2. Attempt to list products or create a test order using the CommerceJS API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the CommerceJS API key immediately."
  },
  "Commodities": {
    "service": "Commodities API",
    "category": "Commodity Data",
    "impact": "Unauthorized access to and modification of commodity data, potentially leading to data scraping or misuse of market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Commodities API key.\n2. Use the key to fetch commodity data via the Commodities API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Commodities API key immediately."
  },
  "CompanyHub": {
    "service": "CompanyHub",
    "category": "CRM Tool",
    "impact": "Unauthorized access to and manipulation of CRM data, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "High",
    "poc_template": "1. Locate exposed CompanyHub key.\n2. Attempt to list or modify CRM data using the CompanyHub API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the CompanyHub key immediately."
  },
  "Confluent": {
    "service": "Confluent",
    "category": "Streaming Platform (Kafka)",
    "impact": "Unauthorized access to and management of Apache Kafka clusters, potentially leading to data compromise, service disruption, or resource abuse within a real-time data streaming environment.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Confluent API key.\n2. Attempt to list or manage Kafka clusters/topics using the Confluent API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Confluent API key immediately and implement appropriate access controls."
  },
  "ContentfulPersonalAccessToken": {
    "service": "Contentful",
    "category": "Content Management System (CMS)",
    "impact": "Unauthorized access to and modification of digital content, potentially leading to unauthorized content publishing, content manipulation, or deletion of crucial website/application content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Contentful Personal Access Token.\n2. Attempt to retrieve or modify content entries via the Contentful API with the found token.\n3. Verify successful content manipulation.",
    "remediation": "Revoke the Contentful Personal Access Token immediately and generate a new one, storing it securely."
  },
  "ConversionTools": {
    "service": "ConversionTools",
    "category": "Data Conversion",
    "impact": "Unauthorized access to and performance of various data conversion tasks, potentially leading to resource abuse, unauthorized file conversions, or exposure of converted file content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ConversionTools API key.\n2. Attempt to initiate a data conversion using the ConversionTools API with the found key.\n3. Verify successful conversion.",
    "remediation": "Rotate the ConversionTools API key immediately."
  },
  "ConvertApi": {
    "service": "ConvertAPI",
    "category": "File Conversion",
    "impact": "Unauthorized access to and performance of file conversions, potentially leading to resource abuse, unauthorized file conversions, or exposure of converted file content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ConvertAPI key.\n2. Attempt to initiate a file conversion using the ConvertAPI with the found key.\n3. Verify successful conversion.",
    "remediation": "Rotate the ConvertAPI key immediately."
  },
  "Convertkit": {
    "service": "Convertkit",
    "category": "Email Marketing",
    "impact": "Unauthorized access to and management of email marketing campaigns and subscriber data, potentially leading to unauthorized email sending, spamming, or exposure of sensitive subscriber lists.",
    "severity": "High",
    "poc_template": "1. Locate exposed Convertkit API key.\n2. Attempt to list subscribers or send a test email campaign using the Convertkit API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Convertkit API key immediately."
  },
  "Convier": {
    "service": "Convier",
    "category": "Event Data Management",
    "impact": "Unauthorized access to and management of event data, potentially leading to event manipulation, exposure of sensitive event details, or disruption of event verification services.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Convier key.\n2. Attempt to list or verify event data using the Convier API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Convier key immediately."
  },
  "Copper": {
    "service": "Copper",
    "category": "CRM Software",
    "impact": "Unauthorized access to and modification of customer data and interactions, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Copper API key.\n2. Attempt to retrieve or modify customer data (e.g., contacts, opportunities) using the Copper API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Copper API key immediately."
  },
  "Couchbase": {
    "service": "Couchbase",
    "category": "NoSQL Cloud Database",
    "impact": "Unauthorized access to and modification of data within the Couchbase database, potentially leading to data theft, data corruption, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Couchbase credentials.\n2. Attempt to connect to the Couchbase database and query/modify data.\n3. Verify successful data access and manipulation.",
    "remediation": "Revoke the exposed Couchbase credentials and generate new, strong credentials immediately. Implement proper access controls."
  },
  "CountryLayer": {
    "service": "CountryLayer",
    "category": "Country Information API",
    "impact": "Unauthorized access to country information, potentially leading to excessive API usage charges or data scraping of geopolitical data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed CountryLayer API key.\n2. Use the key to fetch country information via the CountryLayer API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the CountryLayer API key immediately."
  },
  "Courier": {
    "service": "Courier",
    "category": "Notification Service",
    "impact": "Unauthorized management and sending of notifications through multiple channels, potentially leading to unauthorized messaging, spamming, or disruption of critical alerts.",
    "severity": "High",
    "poc_template": "1. Locate exposed Courier API key.\n2. Attempt to send a test notification using the Courier API with the found key.\n3. Verify successful notification delivery.",
    "remediation": "Revoke and regenerate the Courier API key immediately."
  },
  "Coveralls": {
    "service": "Coveralls",
    "category": "Code Coverage Tracking",
    "impact": "Unauthorized access to and modification of code coverage data, potentially leading to the injection of false coverage reports, manipulation of quality metrics, or exposure of sensitive code testing information.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Coveralls token.\n2. Attempt to submit or retrieve code coverage data for a repository using the Coveralls API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Coveralls token and generate a new one immediately."
  },
  "CraftMyPDF": {
    "service": "CraftMyPDF",
    "category": "PDF Generation",
    "impact": "Unauthorized access to and management of PDF generation tasks, potentially leading to the creation of unauthorized documents, resource abuse, or exposure of sensitive data used in templates.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed CraftMyPDF API key.\n2. Attempt to generate a PDF from a template using the CraftMyPDF API with the found key.\n3. Verify successful PDF generation.",
    "remediation": "Rotate the CraftMyPDF API key immediately."
  },
  "Crowdin": {
    "service": "Crowdin",
    "category": "Localization Management",
    "impact": "Unauthorized access to and management of localization projects and resources, potentially leading to content manipulation, exposure of sensitive translation data, or disruption of localization workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Crowdin API key.\n2. Attempt to list projects or upload source files using the Crowdin API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Crowdin API key immediately."
  },
  "CryptoCompare": {
    "service": "CryptoCompare",
    "category": "Cryptocurrency Market Data",
    "impact": "Unauthorized access to cryptocurrency market data, potentially leading to data scraping or misuse of market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed CryptoCompare API key.\n2. Use the key to fetch cryptocurrency market data via the CryptoCompare API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the CryptoCompare API key immediately."
  },
  "CurrencyCloud": {
    "service": "Currencycloud",
    "category": "Payments Platform",
    "impact": "Unauthorized access to and management of global payment services, including making payments and managing currency risk, potentially leading to financial fraud, unauthorized transfers, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Currencycloud API keys.\n2. Attempt to retrieve account balances or initiate a payment using the Currencycloud API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke and regenerate the Currencycloud API keys. Review all transaction logs for unauthorized activity."
  },
  "CurrencyScoop": {
    "service": "CurrencyScoop",
    "category": "Currency Data",
    "impact": "Unauthorized access to real-time and historical exchange rates, potentially leading to excessive API usage charges or data scraping of financial market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed CurrencyScoop API key.\n2. Use the key to fetch currency exchange rates via the CurrencyScoop API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the CurrencyScoop API key immediately."
  },
  "Currencyfreaks": {
    "service": "Currencyfreaks",
    "category": "Currency Exchange & Conversion",
    "impact": "Unauthorized access to exchange rates and currency conversion services, potentially leading to excessive API usage charges or data scraping of financial market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Currencyfreaks API key.\n2. Use the key to fetch exchange rate data via the Currencyfreaks API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Currencyfreaks API key immediately."
  },
  "Currencylayer": {
    "service": "Currencylayer",
    "category": "Currency Exchange & Conversion",
    "impact": "Unauthorized reading of currency data, potentially leading to excessive API usage charges or data scraping of financial market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Currencylayer API key.\n2. Use the key to fetch currency data via the Currencylayer API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Currencylayer API key immediately."
  },
  "CurrentsAPI": {
    "service": "CurrentsAPI",
    "category": "News & Trends Data",
    "impact": "Unauthorized access to the latest news and trends, potentially leading to excessive API usage charges or data scraping of news content.",
    "severity": "Low",
    "poc_template": "1. Locate exposed CurrentsAPI key.\n2. Use the key to retrieve news data via the CurrentsAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the CurrentsAPI key immediately."
  },
  "CustomerGuru": {
    "service": "CustomerGuru",
    "category": "Feedback Platform",
    "impact": "Unauthorized access to and management of customer feedback data, potentially leading to exposure of sensitive customer opinions, manipulation of feedback metrics, or disruption of feedback collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed CustomerGuru API keys/secrets.\n2. Attempt to retrieve or modify customer feedback data using the CustomerGuru API with the found credentials.\n3. Verify successful data interaction.",
    "remediation": "Revoke and regenerate the CustomerGuru API keys/secrets immediately."
  },
  "CustomerIO": {
    "service": "CustomerIO",
    "category": "Customer Messaging",
    "impact": "Unauthorized interaction with the Customer.io service, allowing for the management of customer data and the triggering of automated emails, push notifications, and SMS messages. This could lead to unauthorized communication with customers, data exfiltration, or spamming.",
    "severity": "High",
    "poc_template": "1. Locate exposed Customer.io API keys.\n2. Attempt to retrieve customer profiles or trigger an event to send a message using the Customer.io API with the found keys.\n3. Verify successful API interaction and message initiation.",
    "remediation": "Revoke and regenerate the Customer.io API keys immediately."
  }
}






































{
  "D7Network": {
    "service": "D7Network",
    "category": "Messaging Service",
    "impact": "Unauthorized sending of SMS and other types of messages, potentially leading to spamming, phishing attempts, or significant financial cost due to message charges.",
    "severity": "High",
    "poc_template": "1. Locate exposed D7Network credentials.\n2. Attempt to send a test SMS message using the D7Network API with the found credentials.\n3. Verify successful message delivery.",
    "remediation": "Revoke and regenerate D7Network credentials immediately."
  },
  "Dandelion": {
    "service": "Dandelion",
    "category": "Text Analysis",
    "impact": "Unauthorized access to and utilization of text analysis services, potentially leading to excessive API usage charges or the processing of sensitive text data without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Dandelion token.\n2. Attempt to analyze sample text using the Dandelion API with the found token.\n3. Verify successful text analysis.",
    "remediation": "Rotate the Dandelion token immediately."
  },
  "Dareboost": {
    "service": "Dareboost",
    "category": "Website Performance Monitoring",
    "impact": "Unauthorized access to and modification of website performance monitoring configurations, potentially leading to disabling monitoring, altering alerts, or exposing sensitive performance data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Dareboost API key.\n2. Attempt to list or modify performance monitoring settings using the Dareboost API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Dareboost API key immediately."
  },
  "DataGov": {
    "service": "Data.gov",
    "category": "Government Data",
    "impact": "Unauthorized access to and retrieval of U.S. government datasets, potentially leading to excessive API usage or data scraping of public information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Data.gov API key.\n2. Use the key to fetch data from a public dataset via the Data.gov API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Data.gov API key immediately."
  },
  "Databox": {
    "service": "Databox",
    "category": "Business Analytics",
    "impact": "Unauthorized access to and modification of business analytics data, potentially leading to data manipulation, exposure of sensitive business insights, or disruption of reporting.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Databox API key.\n2. Attempt to retrieve or modify data within a Databox account using the Databox API with the found key.\n3. Verify successful data interaction.",
    "remediation": "Revoke and regenerate the Databox API key immediately."
  },
  "DatabricksToken": {
    "service": "Databricks",
    "category": "Cloud Data Platform",
    "impact": "Unauthorized authentication and interaction with Databricks services and APIs, potentially leading to data compromise, resource abuse, execution of arbitrary code in notebooks, or unauthorized access to data lakes.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Databricks token.\n2. Configure Databricks CLI with the found token.\n3. Attempt to list workspaces, clusters, or notebooks.\n4. Verify successful access and resource enumeration.",
    "remediation": "Immediately revoke the exposed Databricks token and generate a new one, ensuring it has minimal necessary permissions and a short lifespan."
  },
  "DatadogToken": {
    "service": "Datadog",
    "category": "Monitoring & Security",
    "impact": "Unauthorized access to and management of monitoring data and configurations, potentially leading to disabling alerts, injecting false metrics, or exposing sensitive application performance and security information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Datadog API/Application keys.\n2. Attempt to query metrics, events, or modify dashboards using the Datadog API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Datadog API and Application keys immediately."
  },
  "DeepAIDeepAI": {
    "service": "DeepAI",
    "category": "AI Services",
    "impact": "Unauthorized access to and utilization of various machine learning APIs, potentially leading to resource abuse, generation of harmful content, or exposure of proprietary AI interactions.",
    "severity": "High",
    "poc_template": "1. Locate exposed DeepAI API key.\n2. Attempt to make a request to a DeepAI model (e.g., generate an image, analyze text) using the found key.\n3. Verify successful API interaction and response.",
    "remediation": "Revoke and regenerate the DeepAI API key immediately."
  },
  "DeepSeek": {
    "service": "DeepSeek",
    "category": "AI Services (LLMs)",
    "impact": "Unauthorized access to and usage of DeepSeek's large language models, potentially leading to resource abuse, generation of harmful or unauthorized content, or exposure of proprietary AI interactions.",
    "severity": "High",
    "poc_template": "1. Locate exposed DeepSeek API key.\n2. Attempt to make a request to a DeepSeek LLM (e.g., generate text, complete a prompt) using the found key.\n3. Verify successful API interaction and response.",
    "remediation": "Revoke and regenerate the DeepSeek API key immediately."
  },
  "Deepgram": {
    "service": "Deepgram",
    "category": "Automatic Speech Recognition (ASR)",
    "impact": "Unauthorized access to and utilization of Deepgram's ASR capabilities, potentially leading to excessive API usage charges or the transcription of sensitive audio without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Deepgram API key.\n2. Attempt to transcribe an audio file using the Deepgram API with the found key.\n3. Verify successful transcription.",
    "remediation": "Rotate the Deepgram API key immediately."
  },
  "Delighted": {
    "service": "Delighted",
    "category": "Customer Feedback",
    "impact": "Unauthorized access to and management of customer feedback data, potentially leading to exposure of sensitive customer opinions, manipulation of feedback metrics, or disruption of feedback collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Delighted API key.\n2. Attempt to retrieve or modify customer feedback using the Delighted API with the found key.\n3. Verify successful data interaction.",
    "remediation": "Revoke and regenerate the Delighted API key immediately."
  },
  "Demio": {
    "service": "Demio",
    "category": "Webinar Platform",
    "impact": "Unauthorized access to and management of webinar data, including attendee lists, recordings, and analytics, potentially leading to exposure of sensitive event information or disruption of webinar operations.",
    "severity": "High",
    "poc_template": "1. Locate exposed Demio API key.\n2. Attempt to list webinars or retrieve attendee data using the Demio API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Demio API key immediately."
  },
  "DenoDeploy": {
    "service": "DenoDeploy",
    "category": "Cloud Deployment",
    "impact": "Unauthorized access to and management of JavaScript and TypeScript application deployments, potentially leading to unauthorized code deployments, service disruption, or injection of malicious code into live applications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed DenoDeploy token.\n2. Attempt to list or redeploy applications using the DenoDeploy API with the found token.\n3. Verify successful deployment management.",
    "remediation": "Revoke the DenoDeploy token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Deputy": {
    "service": "Deputy",
    "category": "Workforce Management",
    "impact": "Unauthorized access to and modification of workforce management data, including scheduling, time tracking, and communication, potentially leading to payroll fraud, disruption of operations, or exposure of sensitive employee information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Deputy API key.\n2. Attempt to retrieve or modify employee schedules or time entries using the Deputy API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Deputy API key immediately."
  },
  "DetectLanguage": {
    "service": "DetectLanguage",
    "category": "Language Detection",
    "impact": "Unauthorized access to language detection functionalities, potentially leading to excessive API usage charges or the processing of sensitive text data without consent.",
    "severity": "Low",
    "poc_template": "1. Locate exposed DetectLanguage API key.\n2. Use the key to detect the language of a sample text via the DetectLanguage API.\n3. Verify successful language detection.",
    "remediation": "Rotate the DetectLanguage API key immediately."
  },
  "Detectify": {
    "service": "Detectify",
    "category": "Web Application Security",
    "impact": "Unauthorized access to and management of web application security scans and findings, potentially leading to the exposure of vulnerabilities, disruption of security assessments, or injection of false scan results.",
    "severity": "High",
    "poc_template": "1. Locate exposed Detectify API key.\n2. Attempt to list or initiate a security scan for a website using the Detectify API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Detectify API key immediately."
  },
  "Dfuse": {
    "service": "Dfuse",
    "category": "Blockchain API",
    "impact": "Unauthorized access to and interaction with blockchain data and infrastructure, potentially leading to data scraping, resource abuse, or monitoring of blockchain activities.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Dfuse API key.\n2. Attempt to query blockchain data (e.g., transactions, blocks) using the Dfuse API with the found key.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Dfuse API key immediately."
  },
  "Diffbot": {
    "service": "Diffbot",
    "category": "Web Data Extraction",
    "impact": "Unauthorized access to and utilization of web page data extraction services, potentially leading to excessive API usage charges or the scraping of sensitive content from websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Diffbot API token.\n2. Attempt to extract data from a web page using the Diffbot API with the found token.\n3. Verify successful data extraction.",
    "remediation": "Rotate the Diffbot API token immediately."
  },
  "Diggernaut": {
    "service": "Diggernaut",
    "category": "Web Scraping",
    "impact": "Unauthorized access to and management of web scraping projects and data, potentially leading to data exfiltration, resource abuse, or execution of malicious scraping operations.",
    "severity": "High",
    "poc_template": "1. Locate exposed Diggernaut API key.\n2. Attempt to list or run a scraping project using the Diggernaut API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Diggernaut API key immediately."
  },
  "DigitalOceanToken": {
    "service": "DigitalOcean",
    "category": "Cloud Infrastructure",
    "impact": "Unauthorized access to and management of cloud services, including compute power, storage, and networking, potentially leading to resource abuse, data exfiltration, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed DigitalOcean token.\n2. Configure `doctl` (DigitalOcean CLI) with the found token.\n3. Attempt to list droplets or manage resources.\n4. Verify successful access and resource enumeration.",
    "remediation": "Immediately revoke the exposed DigitalOcean token and generate a new one, ensuring it has minimal necessary permissions."
  },
  "DigitalOceanV2": {
    "service": "DigitalOcean",
    "category": "Cloud Infrastructure",
    "impact": "Unauthorized access to and management of cloud resources, including droplets, volumes, and networks, potentially leading to resource abuse, data exfiltration, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed DigitalOcean API key.\n2. Configure `doctl` (DigitalOcean CLI) with the found key.\n3. Attempt to list droplets or manage resources.\n4. Verify successful access and resource enumeration.",
    "remediation": "Immediately revoke the exposed DigitalOcean API key and generate a new one, ensuring it has minimal necessary permissions."
  },
  "DiscordBotToken": {
    "service": "Discord",
    "category": "Chat Platform (Bot Management)",
    "impact": "Unauthorized control over a Discord bot, allowing for sending messages, managing channels, kicking/banning users, or accessing private server information, potentially leading to spam, harassment, or data leakage within Discord communities.",
    "severity": "High",
    "poc_template": "1. Locate exposed Discord bot token.\n2. Use a Discord bot library or direct API calls to interact with the Discord API using the found token (e.g., list guilds, send a message to a channel the bot is in).\n3. Verify successful bot control.",
    "remediation": "Immediately revoke the exposed Discord bot token in the Discord Developer Portal and generate a new one."
  },
  "DiscordWebhook": {
    "service": "Discord",
    "category": "Chat Platform (Messaging)",
    "impact": "Unauthorized sending of messages to a Discord channel, potentially leading to spamming, phishing attempts, or disruption of channel communication.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Discord webhook URL.\n2. Send a test message to the webhook URL using a simple POST request (e.g., `curl -H 'Content-Type: application/json' -d '{\"content\": \"Test message from webhook\"}' <webhook_url>`).\n3. Verify the message appears in the Discord channel.",
    "remediation": "Delete the exposed Discord webhook in the Discord channel settings immediately."
  },
  "Disqus": {
    "service": "Disqus",
    "category": "Community Platform",
    "impact": "Unauthorized access to and management of comments and user data, potentially leading to comment manipulation, user impersonation, or exposure of sensitive discussion content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Disqus API key.\n2. Attempt to list comments or manage user data using the Disqus API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Disqus API key immediately."
  },
  "Ditto": {
    "service": "Ditto",
    "category": "Word Variant API",
    "impact": "Unauthorized access to word variant services, potentially leading to excessive API usage charges or data scraping of linguistic variations.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Ditto API key.\n2. Use the key to retrieve word variants via the Ditto API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Ditto API key immediately."
  },
  "Dnscheck": {
    "service": "Dnscheck",
    "category": "DNS Monitoring",
    "impact": "Unauthorized access to and management of DNS monitoring configurations, potentially leading to disabling checks, altering alerts, or exposing sensitive DNS records.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Dnscheck API key.\n2. Attempt to list or modify DNS monitoring configurations using the Dnscheck API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Dnscheck API key immediately."
  },
  "Docker": {
    "service": "Docker",
    "category": "Containerization",
    "impact": "Unauthorized ability to pull images from private registries, potentially leading to access to proprietary software, sensitive data embedded in images, or reconnaissance of internal application components.",
    "severity": "High",
    "poc_template": "1. Locate exposed Docker credentials.\n2. Attempt to log in to a Docker private registry using 'docker login' with the found credentials.\n3. Verify successful authentication and attempt to pull an image.",
    "remediation": "Rotate Docker credentials immediately. For private registries, ensure only necessary permissions are granted and consider using short-lived tokens or external credential stores."
  },
  "Dockerhub": {
    "service": "Dockerhub",
    "category": "Container Registry",
    "impact": "Unauthorized access to and management of container images in Docker Hub, potentially allowing for the pulling of private images, pushing of malicious images, or disruption of image distribution pipelines.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Docker Hub personal access token (PAT).\n2. Attempt to log in to Docker Hub using 'docker login' with the found PAT.\n3. Verify successful authentication and ability to list or pull private repositories.",
    "remediation": "Immediately revoke the exposed Docker Hub personal access token and generate a new one with restricted permissions. Review audit logs for unauthorized access or image modifications."
  },
  "Docparser": {
    "service": "Docparser",
    "category": "Document Processing",
    "impact": "Unauthorized access to and manipulation of data extracted from PDFs and scanned documents, potentially leading to data theft, data corruption, or exposure of sensitive document content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Docparser API key.\n2. Attempt to list or process a document using the Docparser API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Docparser API key immediately."
  },
  "Documo": {
    "service": "Documo",
    "category": "Document Management",
    "impact": "Unauthorized creation, reading, updating, and deletion of documents, potentially leading to document manipulation, data exfiltration, or disruption of document workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Documo API key.\n2. Attempt to create, read, update, or delete a document using the Documo API with the found key.\n3. Verify successful document manipulation.",
    "remediation": "Revoke and regenerate the Documo API key immediately."
  },
  "Docusign": {
    "service": "Docusign",
    "category": "Electronic Signature & Transaction Management",
    "impact": "Unauthorized access to and management of digital transactions and documents, potentially leading to unauthorized signing, document tampering, or exposure of sensitive contract information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Docusign credentials.\n2. Attempt to access or sign documents using the Docusign API.\n3. Verify successful access or signing action.",
    "remediation": "Revoke the exposed Docusign credentials and generate new, strong credentials immediately. Review audit logs for unauthorized activities."
  },
  "Doppler": {
    "service": "Doppler",
    "category": "Secrets Management",
    "impact": "Unauthorized access to and management of environment variables and secrets, potentially leading to complete compromise of applications and infrastructure by exposing sensitive credentials, API keys, and configuration data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Doppler token.\n2. Configure Doppler CLI with the found token.\n3. Attempt to list projects, environments, or retrieve secrets.\n4. Verify successful access and secret retrieval.",
    "remediation": "Immediately revoke the exposed Doppler token and generate a new one with minimal necessary permissions. Review Doppler audit logs for any unauthorized access."
  },
  "Dotmailer": {
    "service": "Dotmailer",
    "category": "Email Marketing Automation",
    "impact": "Unauthorized access to and management of email campaigns and related data, potentially leading to unauthorized email sending, spamming, or exposure of sensitive subscriber lists.",
    "severity": "High",
    "poc_template": "1. Locate exposed Dotmailer API key.\n2. Attempt to list contacts or send a test email campaign using the Dotmailer API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Dotmailer API key immediately."
  },
  "Dovico": {
    "service": "Dovico",
    "category": "Time Tracking & Project Management",
    "impact": "Unauthorized access to and management of time tracking and project data, potentially leading to inaccurate billing, project overruns, or exposure of sensitive employee work hours and project details.",
    "severity": "High",
    "poc_template": "1. Locate exposed Dovico keys.\n2. Attempt to list or modify time entries or project data using the Dovico API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Dovico keys immediately."
  },
  "DronaHQ": {
    "service": "DronaHQ",
    "category": "Internal Tools & Applications",
    "impact": "Unauthorized access to and management of internal tools and applications, potentially leading to data breaches, application manipulation, or disruption of internal business processes.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed DronaHQ keys.\n2. Attempt to list or modify applications/data within the DronaHQ platform using the API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the DronaHQ keys immediately."
  },
  "DroneCI": {
    "service": "DroneCI",
    "category": "Continuous Integration",
    "impact": "Unauthorized access to and control over CI/CD pipelines, potentially leading to unauthorized code deployments, access to build artifacts, or disruption of continuous integration workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed DroneCI token.\n2. Attempt to list repositories or trigger a build using the DroneCI API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the DroneCI token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Dropbox": {
    "service": "Dropbox",
    "category": "File Hosting & Cloud Storage",
    "impact": "Unauthorized access to and management of files and folders in a Dropbox account, potentially leading to data theft, deletion, or unauthorized file sharing.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Dropbox API key.\n2. Attempt to list files or download content from a Dropbox account using the Dropbox API with the found key.\n3. Verify successful data access and manipulation.",
    "remediation": "Revoke the exposed Dropbox API key immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Duply": {
    "service": "Duply",
    "category": "Image Generation",
    "impact": "Unauthorized fetching and creation of images, potentially leading to excessive API usage charges or the generation of malicious/unauthorized content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Duply API key.\n2. Attempt to fetch or create an image using the Duply API with the found key.\n3. Verify successful image interaction.",
    "remediation": "Rotate the Duply API key immediately."
  },
  "Dwolla": {
    "service": "Dwolla",
    "category": "Payment Services",
    "impact": "Unauthorized access to and management of payment services, including sending, receiving, and facilitating payments, potentially leading to financial fraud, unauthorized fund transfers, or exposure of sensitive payment information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Dwolla API keys.\n2. Attempt to retrieve account information or initiate a payment using the Dwolla API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke and regenerate the Dwolla API keys. Review all transaction logs for unauthorized activity."
  },
  "Dynalist": {
    "service": "Dynalist",
    "category": "Outlining App",
    "impact": "Unauthorized access to and manipulation of hierarchical lists, potentially leading to data theft, data corruption, or exposure of sensitive outline content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Dynalist API token.\n2. Attempt to list or modify lists/items using the Dynalist API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the Dynalist API token immediately and generate a new one, storing it securely."
  },
  "Dyspatch": {
    "service": "Dyspatch",
    "category": "Transactional Email",
    "impact": "Unauthorized access to and management of email templates and sending operations, potentially leading to unauthorized transactional email sending, brand impersonation, or exposure of sensitive email content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Dyspatch API key.\n2. Attempt to list templates or send a test transactional email using the Dyspatch API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Dyspatch API key immediately."
  },
  "EagleEyeNetworks": {
    "service": "Eagle Eye Networks",
    "category": "Cloud Video Surveillance",
    "impact": "Unauthorized access to and management of cloud-based video surveillance data, potentially leading to unauthorized viewing of live/recorded footage, data deletion, or privacy breaches.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Eagle Eye Networks credentials.\n2. Attempt to access surveillance footage or modify camera settings using the Eagle Eye Networks API.\n3. Verify successful access and control.",
    "remediation": "Revoke the exposed Eagle Eye Networks credentials and generate new, strong credentials immediately. Review audit logs for unauthorized activities."
  },
  "EasyInsight": {
    "service": "EasyInsight",
    "category": "Business Intelligence",
    "impact": "Unauthorized access to and management of data within the business intelligence platform, potentially leading to exposure of sensitive business data, manipulation of reports, or disruption of analytics.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed EasyInsight API key.\n2. Attempt to retrieve or modify data within EasyInsight using the EasyInsight API with the found key.\n3. Verify successful data interaction.",
    "remediation": "Revoke and regenerate the EasyInsight API key immediately."
  },
  "EcoStruxureITEcoStruxure": {
    "service": "EcoStruxure IT",
    "category": "IT Infrastructure Management",
    "impact": "Unauthorized access to and management of IT infrastructure data and operations, potentially leading to monitoring system manipulation, data center disruptions, or exposure of sensitive infrastructure details.",
    "severity": "High",
    "poc_template": "1. Locate exposed EcoStruxure IT API key.\n2. Attempt to list devices or retrieve monitoring data using the EcoStruxure IT API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the EcoStruxure IT API key immediately."
  },
  "Edamam": {
    "service": "Edamam",
    "category": "Nutrition Analysis & Recipes",
    "impact": "Unauthorized access to and modification of nutrition data and performance of diet analysis, potentially leading to excessive API usage charges or manipulation of dietary recommendations.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Edamam API key.\n2. Use the key to analyze nutrition for a food item or search recipes via the Edamam API.\n3. Verify successful data retrieval/analysis.",
    "remediation": "Rotate the Edamam API key immediately."
  },
  "EdenAIEdenAI": {
    "service": "EdenAI",
    "category": "AI API Aggregator",
    "impact": "Unauthorized access to and utilization of multiple AI engines through a unified API, potentially leading to resource abuse, generation of harmful content, or exposure of proprietary AI interactions across various services.",
    "severity": "High",
    "poc_template": "1. Locate exposed EdenAI API key.\n2. Attempt to make a request to an integrated AI engine (e.g., text generation, image recognition) using the EdenAI API with the found key.\n3. Verify successful API interaction and response.",
    "remediation": "Revoke and regenerate the EdenAI API key immediately."
  },
  "EightxEight8x8": {
    "service": "8x8",
    "category": "Cloud Communication",
    "impact": "Unauthorized access to and management of cloud-based communication services (voice, video, chat, contact center), potentially leading to unauthorized calls, eavesdropping, or disruption of communication systems.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed 8x8 credentials.\n2. Attempt to access communication logs, make calls, or modify contact center settings via the 8x8 API.\n3. Verify successful administrative action.",
    "remediation": "Revoke and regenerate 8x8 credentials immediately. Review all audit logs for unauthorized activities."
  },
  "ElasticEmail": {
    "service": "ElasticEmail",
    "category": "Email Marketing Service",
    "impact": "Unauthorized sending of emails, management of contacts, and access to other features, potentially leading to spamming, phishing attempts, or exposure of sensitive contact lists.",
    "severity": "High",
    "poc_template": "1. Locate exposed ElasticEmail API key.\n2. Attempt to send a test email or list contacts using the ElasticEmail API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the ElasticEmail API key immediately."
  },
  "ElevenLabs": {
    "service": "ElevenLabs",
    "category": "AI Voice Synthesis",
    "impact": "Unauthorized access to and utilization of voice synthesis and other AI-powered tools, potentially leading to excessive API usage charges, generation of unauthorized audio content, or impersonation of voices.",
    "severity": "High",
    "poc_template": "1. Locate exposed ElevenLabs API key.\n2. Attempt to generate speech from text using the ElevenLabs API with the found key.\n3. Verify successful audio generation.",
    "remediation": "Revoke and regenerate the ElevenLabs API key immediately."
  },
  "Enablex": {
    "service": "Enablex",
    "category": "Communication Platform",
    "impact": "Unauthorized access to and management of voice, video, and messaging APIs, potentially leading to unauthorized calls/messages, eavesdropping, or service disruption.",
    "severity": "High",
    "poc_template": "1. Locate exposed Enablex credentials.\n2. Attempt to create or join a communication session using the Enablex API with the found credentials.\n3. Verify successful session initiation or management.",
    "remediation": "Revoke and regenerate Enablex credentials immediately."
  },
  "EndorLabs": {
    "service": "EndorLabs",
    "category": "Software Supply Chain Security",
    "impact": "Unauthorized authentication and interaction with Endorlabs services, potentially leading to access to software supply chain analysis results, security configurations, or injection of false data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Endorlabs API key.\n2. Attempt to list projects or retrieve security findings using the Endorlabs API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Endorlabs API key and generate a new one immediately. Review audit logs for unauthorized access."
  },
  "Enigma": {
    "service": "Enigma",
    "category": "Data Intelligence",
    "impact": "Unauthorized access to comprehensive business data, potentially leading to data scraping, competitive intelligence gathering, or misuse of proprietary business information.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Enigma API key.\n2. Use the key to query business data via the Enigma API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Enigma API key immediately."
  },
  "EnvoyApiKey": {
    "service": "Envoy",
    "category": "Visitor Management",
    "impact": "Unauthorized access to and management of visitor data and other resources, potentially leading to exposure of sensitive visitor information, manipulation of visitor logs, or disruption of reception operations.",
    "severity": "High",
    "poc_template": "1. Locate exposed Envoy API key.\n2. Attempt to list visitors or check-in/out a test visitor using the Envoy API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Envoy API key immediately."
  },
  "Eraser": {
    "service": "Eraser",
    "category": "Diagram Generation",
    "impact": "Unauthorized authentication and interaction with the Eraser API, potentially leading to the generation of unauthorized diagrams or exposure of diagram definitions (DSL).",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Eraser API token.\n2. Attempt to generate a diagram or list existing diagrams using the Eraser API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Eraser API token immediately."
  },
  "Etherscan": {
    "service": "Etherscan",
    "category": "Blockchain Explorer (Ethereum)",
    "impact": "Unauthorized access to various functionalities provided by Etherscan, potentially leading to excessive API usage charges or the scraping of Ethereum blockchain data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Etherscan API key.\n2. Use the key to query Ethereum blockchain data (e.g., transaction history for an address) via the Etherscan API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Etherscan API key immediately."
  },
  "Ethplorer": {
    "service": "Ethplorer",
    "category": "Ethereum Blockchain Data",
    "impact": "Unauthorized interaction with the Ethplorer service, potentially leading to excessive API usage charges or the scraping of Ethereum blockchain data and analytics.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Ethplorer API key.\n2. Use the key to query Ethereum blockchain data (e.g., token balances for an address) via the Ethplorer API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Ethplorer API key immediately."
  },
  "Eventbrite": {
    "service": "Eventbrite",
    "category": "Event Management & Ticketing",
    "impact": "Unauthorized access to and management of event data, potentially leading to event manipulation, exposure of attendee information, or ticketing fraud.",
    "severity": "High",
    "poc_template": "1. Locate exposed Eventbrite API key.\n2. Attempt to list events or retrieve attendee information using the Eventbrite API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Eventbrite API key immediately."
  },
  "Everhour": {
    "service": "Everhour",
    "category": "Time Tracking Software",
    "impact": "Unauthorized access to and management of project and time tracking data, potentially leading to inaccurate billing, project overruns, or exposure of sensitive employee work hours.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Everhour API key.\n2. Attempt to list or modify time entries or project data using the Everhour API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Everhour API key immediately."
  },
  "ExchangeRateAPI": {
    "service": "ExchangeRateAPI",
    "category": "Currency Exchange Rates",
    "impact": "Unauthorized access to currency exchange rate data, potentially leading to excessive API usage charges or data scraping of financial market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed ExchangeRateAPI key.\n2. Use the key to fetch exchange rates via the ExchangeRateAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ExchangeRateAPI key immediately."
  },
  "ExchangeRatesAPI": {
    "service": "ExchangeRatesAPI",
    "category": "Currency Exchange Rates",
    "impact": "Unauthorized access to exchange rate data, potentially leading to excessive API usage charges or data scraping of financial market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed ExchangeRatesAPI key.\n2. Use the key to fetch exchange rate data via the ExchangeRatesAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ExchangeRatesAPI key immediately."
  },
  "ExportSDK": {
    "service": "ExportSDK",
    "category": "Data Export & PDF Generation",
    "impact": "Unauthorized authentication for API requests and generation of documents, potentially leading to resource abuse, creation of unauthorized documents, or exposure of sensitive data used in exports.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ExportSDK keys.\n2. Attempt to generate a PDF document using the ExportSDK API with the found keys.\n3. Verify successful document generation.",
    "remediation": "Rotate the ExportSDK keys immediately."
  },
  "ExtractorAPI": {
    "service": "ExtractorAPI",
    "category": "Data Extraction",
    "impact": "Unauthorized access to and extraction of data from various sources, potentially leading to data exfiltration or resource abuse.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ExtractorAPI key.\n2. Attempt to extract data from a source using the ExtractorAPI with the found key.\n3. Verify successful data extraction.",
    "remediation": "Rotate the ExtractorAPI key immediately."
  },
  "FTP": {
    "service": "FTP",
    "category": "File Transfer Protocol",
    "impact": "Unauthorized reading and potentially writing of files on an FTP server, leading to data exfiltration, injection of malicious files, or disruption of hosted content.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed FTP password.\n2. Attempt to connect to the FTP server using the found credentials (username and password).\n3. Verify successful connection and attempt to list, download, or upload files.",
    "remediation": "Change the FTP password immediately to a strong, unique password. Consider using SFTP/FTPS for secure file transfer and restrict IP access."
  },
  "FXMarket": {
    "service": "Fxmarket",
    "category": "Financial Market Data",
    "impact": "Unauthorized access to and modification of currency trading data, potentially leading to data scraping or manipulation of financial market information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Fxmarket API key.\n2. Use the key to fetch or attempt to modify currency trading data via the Fxmarket API.\n3. Verify successful data retrieval or manipulation.",
    "remediation": "Rotate the Fxmarket API key immediately."
  },
  "FacePlusPlusFace": {
    "service": "Face++",
    "category": "Facial Recognition",
    "impact": "Unauthorized access to and manipulation of facial recognition services, potentially leading to resource abuse, unauthorized face detection/analysis, or privacy breaches if sensitive facial data is processed.",
    "severity": "High",
    "poc_template": "1. Locate exposed Face++ API keys and secrets.\n2. Attempt to detect faces in an image or analyze facial features using the Face++ API with the found credentials.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Face++ API keys and secrets immediately."
  },
  "FacebookOAuth": {
    "service": "Facebook",
    "category": "Social Media & API Access",
    "impact": "Unauthorized authentication of users and access to Facebook's API services on behalf of the user, potentially leading to data exfiltration from user profiles, posting unauthorized content, or accessing private data depending on granted permissions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Facebook OAuth token.\n2. Attempt to access a user's Facebook profile data (e.g., posts, friends list) or post on their behalf using the Facebook Graph API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Invalidate the exposed Facebook OAuth token through Facebook's security settings or by forcing a token refresh/re-authorization for the application. Advise users to review connected apps."
  },
  "FastForex": {
    "service": "FastForex",
    "category": "Foreign Exchange Rate Data",
    "impact": "Unauthorized access to foreign exchange rate data, potentially leading to excessive API usage charges or data scraping of financial market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed FastForex API key.\n2. Use the key to fetch foreign exchange rates via the FastForex API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the FastForex API key immediately."
  },
  "FastlyPersonalToken": {
    "service": "Fastly",
    "category": "CDN & Cloud Services",
    "impact": "Unauthorized authentication for API requests to Fastly services, potentially leading to cache purging, service configuration changes, or access to sensitive CDN logs, severely impacting content delivery and website performance.",
    "severity": "High",
    "poc_template": "1. Locate exposed Fastly personal token.\n2. Attempt to list Fastly services or purge cache for a service using the Fastly API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Fastly personal token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Feedier": {
    "service": "Feedier",
    "category": "Feedback Management",
    "impact": "Unauthorized access to and management of customer feedback data, potentially leading to exposure of sensitive customer opinions, manipulation of feedback metrics, or disruption of feedback collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Feedier API key.\n2. Attempt to retrieve or modify feedback data using the Feedier API with the found key.\n3. Verify successful data interaction.",
    "remediation": "Revoke and regenerate the Feedier API key immediately."
  },
  "Fetchrss": {
    "service": "FetchRSS",
    "category": "RSS Feed Conversion",
    "impact": "Unauthorized management and access to RSS feeds, potentially leading to the creation of unauthorized feeds or data scraping of converted web content.",
    "severity": "Low",
    "poc_template": "1. Locate exposed FetchRSS API key.\n2. Attempt to list or create RSS feeds using the FetchRSS API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the FetchRSS API key immediately."
  },
  "Fibery": {
    "service": "Fibery",
    "category": "Work Management",
    "impact": "Unauthorized access to and modification of data within a Fibery workspace, potentially leading to intellectual property theft, project disruption, or exposure of sensitive knowledge management content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Fibery API token.\n2. Attempt to list or modify entities (e.g., tasks, documents) in a Fibery workspace using the Fibery API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the Fibery API token immediately and generate a new one, storing it securely."
  },
  "FigmaPersonalAccessToken": {
    "service": "Figma",
    "category": "Collaborative Design",
    "impact": "Unauthorized access to and manipulation of design files and other resources on behalf of a user, potentially leading to intellectual property theft, design tampering, or exposure of sensitive design projects.",
    "severity": "High",
    "poc_template": "1. Locate exposed Figma Personal Access Token.\n2. Attempt to list files or export design assets using the Figma API with the found token.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke the Figma Personal Access Token immediately and generate a new one, storing it securely."
  },
  "FileIO": {
    "service": "FileIO",
    "category": "File Sharing",
    "impact": "Unauthorized access to and management of shared files, potentially leading to data exfiltration or unauthorized file deletion.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed FileIO key.\n2. Attempt to access or delete a shared file using the FileIO API with the found key.\n3. Verify successful file interaction.",
    "remediation": "Revoke the exposed FileIO key and generate a new one immediately."
  },
  "Finage": {
    "service": "Finage",
    "category": "Financial Data",
    "impact": "Unauthorized access to and retrieval of financial data for stocks, forex, and cryptocurrencies, potentially leading to data scraping or misuse of market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Finage API key.\n2. Use the key to fetch financial data (e.g., stock prices, forex rates) via the Finage API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Finage API key immediately."
  },
  "FinancialModelingPrep": {
    "service": "FinancialModelingPrep",
    "category": "Financial Data",
    "impact": "Unauthorized access to financial data and related services, potentially leading to data scraping or misuse of market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed FinancialModelingPrep API key.\n2. Use the key to fetch financial data via the FinancialModelingPrep API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the FinancialModelingPrep API key immediately."
  },
  "Findl": {
    "service": "Findl",
    "category": "Data Search & Query",
    "impact": "Unauthorized access to and modification of data, potentially leading to data breaches, data manipulation, or disruption of search functionalities.",
    "severity": "High",
    "poc_template": "1. Locate exposed Findl API key.\n2. Attempt to search or modify data using the Findl API with the found key.\n3. Verify successful data interaction.",
    "remediation": "Revoke and regenerate the Findl API key immediately."
  },
  "Finnhub": {
    "service": "Finnhub",
    "category": "Financial Data Provider",
    "impact": "Unauthorized access to market data including economic calendars, stock prices, and other financial information, potentially leading to data scraping or misuse of financial intelligence.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Finnhub API key.\n2. Use the key to fetch stock data or economic calendar events via the Finnhub API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Finnhub API key immediately."
  },
  "FixerIO": {
    "service": "Fixer.io",
    "category": "Foreign Exchange Rates",
    "impact": "Unauthorized access to current and historical foreign exchange rates, potentially leading to excessive API usage charges or data scraping of financial market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Fixer.io API key.\n2. Use the key to fetch exchange rates via the Fixer.io API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Fixer.io API key immediately."
  },
  "FlatIO": {
    "service": "FlatIO",
    "category": "Music Notation Software",
    "impact": "Unauthorized access to and modification of musical scores and related data, potentially leading to intellectual property theft, score manipulation, or disruption of music creation workflows.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed FlatIO keys.\n2. Attempt to list or modify musical scores using the FlatIO API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the FlatIO keys immediately."
  },
  "Fleetbase": {
    "service": "Fleetbase",
    "category": "Logistics & Supply Chain",
    "impact": "Unauthorized access to and management of logistics data and operations, potentially leading to disruption of supply chains, exposure of sensitive shipping information, or fraudulent activities.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Fleetbase API key.\n2. Attempt to list shipments or modify logistics data using the Fleetbase API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Fleetbase API key immediately."
  },
  "Flexport": {
    "service": "Flexport",
    "category": "Global Logistics",
    "impact": "Unauthorized access to and management of shipping, freight forwarding, and supply chain management services, potentially leading to disruption of logistics, exposure of sensitive shipment details, or fraudulent activities.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Flexport credentials (API keys/tokens).\n2. Attempt to list shipments, track orders, or modify logistics information via the Flexport API.\n3. Verify successful administrative access or data manipulation.",
    "remediation": "Revoke the exposed Flexport credentials and generate new, strong credentials immediately. Review audit logs for unauthorized activities."
  },
  "Flickr": {
    "service": "Flickr",
    "category": "Image & Video Hosting",
    "impact": "Unauthorized access to and modification of user data and performance of various operations within the Flickr ecosystem, potentially leading to content manipulation, privacy breaches, or account impersonation.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Flickr API key.\n2. Attempt to list user photos or modify photo metadata using the Flickr API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Flickr API key immediately."
  },
  "FlightApi": {
    "service": "FlightApi",
    "category": "Flight Data",
    "impact": "Unauthorized access to flight-related data, potentially leading to excessive API usage charges or data scraping of flight information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed FlightApi key.\n2. Use the key to query flight information via the FlightApi.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the FlightApi key immediately."
  },
  "FlightLabs": {
    "service": "FlightLabs",
    "category": "Flight Data",
    "impact": "Unauthorized access to real-time and historical flight data, potentially leading to excessive API usage charges or data scraping of flight information, schedules, and related data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed FlightLabs API key.\n2. Use the key to query flight information via the FlightLabs API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the FlightLabs API key immediately."
  },
  "Flightstats": {
    "service": "Flightstats",
    "category": "Flight Data & Statistics",
    "impact": "Unauthorized access to flight data and statistics, potentially leading to excessive API usage charges or data scraping of flight information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Flightstats API key.\n2. Use the key to retrieve flight information via the Flightstats API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Flightstats API key immediately."
  },
  "Float": {
    "service": "Float",
    "category": "Resource Management",
    "impact": "Unauthorized access to and modification of project data and schedules, potentially leading to project disruption, resource misallocation, or exposure of sensitive planning information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Float API key.\n2. Attempt to list or modify projects/schedules using the Float API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Float API key immediately."
  },
  "FlowFlu": {
    "service": "FlowFlu",
    "category": "CRM & Project Management",
    "impact": "Unauthorized access to and manipulation of customer relationships and project data, potentially leading to data breaches, lead manipulation, or disruption of project workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed FlowFlu API key.\n2. Attempt to list or modify CRM data or project tasks using the FlowFlu API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the FlowFlu API key immediately."
  },
  "Flutterwave": {
    "service": "Flutterwave",
    "category": "Payment Technology",
    "impact": "Unauthorized access to and management of payment services and transactions, potentially leading to financial fraud, unauthorized fund transfers, or exposure of sensitive payment information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Flutterwave API keys.\n2. Attempt to retrieve account balance or initiate a payment using the Flutterwave API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke and regenerate the Flutterwave API keys. Review all transaction logs for unauthorized activity."
  },
  "Fmfw": {
    "service": "FMFW",
    "category": "Cryptocurrency Exchange",
    "impact": "Unauthorized access to and management of account data and performance of trading operations, potentially leading to unauthorized trades, fund manipulation, or exposure of sensitive trading history.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed FMFW API key.\n2. Attempt to retrieve account balance or place an order using the FMFW API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the FMFW API key immediately and enable appropriate security measures like IP whitelisting."
  },
  "FormBucket": {
    "service": "FormBucket",
    "category": "Form Submission Management",
    "impact": "Unauthorized access to and modification of form submission data, potentially leading to data theft, data corruption, or exposure of sensitive information collected through forms.",
    "severity": "High",
    "poc_template": "1. Locate exposed FormBucket credential.\n2. Attempt to access or modify form submissions using the FormBucket API with the found credential.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke the exposed FormBucket credential and generate a new one immediately."
  },
  "FormIO": {
    "service": "FormIO",
    "category": "Form-based Application Platform",
    "impact": "Unauthorized authentication and interaction with Form.io services, potentially leading to data breaches, form manipulation, or unauthorized access to data collected through forms.",
    "severity": "High",
    "poc_template": "1. Locate exposed Form.io JWT token.\n2. Attempt to access or modify form data or submissions using the Form.io API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Invalidate the exposed Form.io JWT token and ensure proper token management and expiration."
  },
  "Formcraft": {
    "service": "Formcraft",
    "category": "Form Building & Data Collection",
    "impact": "Unauthorized access to and management of forms and collected data, potentially leading to data theft, form manipulation, or exposure of sensitive information submitted through forms.",
    "severity": "High",
    "poc_template": "1. Locate exposed Formcraft keys.\n2. Attempt to list or modify forms or collected data using the Formcraft API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Formcraft keys immediately."
  },
  "Formsite": {
    "service": "Formsite",
    "category": "Online Form Builder",
    "impact": "Unauthorized access to and management of forms and data submissions, potentially leading to data theft, form manipulation, or exposure of sensitive information submitted through forms.",
    "severity": "High",
    "poc_template": "1. Locate exposed Formsite API key.\n2. Attempt to list or retrieve data submissions from a form using the Formsite API with the found key.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Formsite API key immediately."
  },
  "FourSquare": {
    "service": "Foursquare",
    "category": "Location Intelligence",
    "impact": "Unauthorized access to and interaction with Foursquare's location intelligence services, potentially leading to excessive API usage charges or data scraping of venue information and user check-ins.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Foursquare API key.\n2. Use the key to search for venues or retrieve location data via the Foursquare API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Foursquare API key immediately."
  },
  "FrameIO": {
    "service": "Frame.io",
    "category": "Video Review & Collaboration",
    "impact": "Unauthorized access to and management of video projects and assets, potentially leading to intellectual property theft, video manipulation, or exposure of sensitive creative content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Frame.io API key.\n2. Attempt to list projects or access video assets using the Frame.io API with the found key.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Frame.io API key immediately."
  },
  "Freshbooks": {
    "service": "FreshBooks",
    "category": "Accounting Software",
    "impact": "Unauthorized access to and modification of accounting data, invoices, and other financial operations, potentially leading to financial fraud, data manipulation, or exposure of sensitive financial records.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed FreshBooks API key.\n2. Attempt to retrieve or modify invoice data or client information using the FreshBooks API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the FreshBooks API key immediately."
  },
  "Freshdesk": {
    "service": "Freshdesk",
    "category": "Customer Support Software",
    "impact": "Unauthorized access to and management of support tickets, contacts, and other customer support data, potentially leading to data breaches, support ticket manipulation, or exposure of sensitive customer interactions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Freshdesk API key.\n2. Attempt to list tickets or retrieve contact information using the Freshdesk API with the found key.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Freshdesk API key immediately."
  },
  "Front": {
    "service": "Front",
    "category": "Customer Communication Hub",
    "impact": "Unauthorized access to and management of customer communication data across various channels (email, social media, SMS), potentially leading to unauthorized messaging, privacy breaches, or exposure of sensitive customer interactions.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Front API key.\n2. Attempt to list conversations or send a message using the Front API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Front API key immediately."
  },
  "Fulcrum": {
    "service": "Fulcrum",
    "category": "Data Collection (Geospatial)",
    "impact": "Unauthorized access to and management of geospatial data collected through the platform, potentially leading to data theft, data corruption, or exposure of sensitive location-based information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Fulcrum API token.\n2. Attempt to list records or download data using the Fulcrum API with the found token.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke the Fulcrum API token immediately and generate a new one, storing it securely."
  },
  "Fullstory": {
    "service": "Fullstory",
    "category": "Digital Experience Analytics",
    "impact": "Unauthorized access to user session data and analytics, potentially leading to privacy breaches, exposure of sensitive user interactions, or misuse of behavioral data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Fullstory keys.\n2. Attempt to retrieve user session data or analytics using the Fullstory API with the found keys.\n3. Verify successful data access.",
    "remediation": "Revoke the exposed Fullstory keys and generate new ones immediately."
  }
}















































{
  "GCP": {
    "service": "Google Cloud Platform",
    "category": "Cloud Provider",
    "impact": "Complete GCP account access, resource manipulation, billing fraud, data exfiltration from storage/databases/compute instances.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed GCP keys.\n2. Configure GCP CLI (gcloud) with found credentials.\n3. Run 'gcloud auth list' and 'gcloud config list' to verify access.\n4. Enumerate accessible resources with 'gcloud compute instances list' or 'gcloud storage ls'.",
    "remediation": "Immediately rotate credentials in GCP IAM & Admin console and review Cloud Audit Logs for unauthorized access."
  },
  "GCPApplicationDefaultCredentials": {
    "service": "Google Cloud Platform",
    "category": "Cloud Provider (Authentication)",
    "impact": "Unauthorized authentication and authorization to Google Cloud services, potentially leading to access to resources based on the permissions granted to the service account or user associated with the credentials, resulting in data breaches, resource manipulation, or service disruption.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed GCP Application Default Credentials (e.g., JSON key file or environment variables).\n2. Attempt to use these credentials with a Google Cloud client library or `gcloud auth application-default print-access-token`.\n3. Verify successful token generation and attempt to access a GCP service (e.g., list S3 buckets, query BigQuery).",
    "remediation": "Immediately revoke or rotate the service account key if it's a downloaded JSON file. If it's a user credential, revoke refresh tokens and reset passwords. Ensure credentials are never hardcoded or exposed in public repositories."
  },
  "GTMetrix": {
    "service": "GTMetrix",
    "category": "Website Performance Monitoring",
    "impact": "Unauthorized access to and management of website performance analytics and monitoring configurations, potentially leading to disabling monitoring, altering alerts, or exposing sensitive performance data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed GTMetrix API key.\n2. Attempt to list or modify website performance tests using the GTMetrix API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the GTMetrix API key immediately."
  },
  "Geckoboard": {
    "service": "Geckoboard",
    "category": "Data Visualization",
    "impact": "Unauthorized access to and modification of real-time dashboards, potentially leading to exposure of sensitive business metrics, manipulation of visualizations, or disruption of data presentation.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Geckoboard API key.\n2. Attempt to list or modify dashboards using the Geckoboard API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Geckoboard API key immediately."
  },
  "Gemini": {
    "service": "Gemini",
    "category": "Cryptocurrency Exchange",
    "impact": "Unauthorized access to and management of account details and performance of transactions, potentially leading to unauthorized cryptocurrency trades, fund transfers, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Gemini API keys.\n2. Attempt to retrieve account balance or initiate a trade using the Gemini API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Gemini API keys immediately and enable appropriate security measures like IP whitelisting."
  },
  "Gengo": {
    "service": "Gengo",
    "category": "Translation Services",
    "impact": "Unauthorized access to and management of translation projects and resources, potentially leading to the creation of unauthorized translation orders, exposure of sensitive content to be translated, or resource abuse.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Gengo API key.\n2. Attempt to list translation jobs or submit a test translation using the Gengo API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Gengo API key immediately."
  },
  "GeoIpifi": {
    "service": "GeoIpifi",
    "category": "Geolocation",
    "impact": "Unauthorized access to geolocation information based on IP addresses, potentially leading to excessive API usage charges or data scraping of location data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed GeoIpifi API key.\n2. Use the key to retrieve geolocation data for an IP address via the GeoIpifi API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the GeoIpifi API key immediately."
  },
  "Geoapify": {
    "service": "Geoapify",
    "category": "Geolocation Services",
    "impact": "Unauthorized access to geolocation services, including geocoding, routing, and places, potentially leading to excessive API usage charges or data scraping of location-based information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Geoapify API key.\n2. Use the key to perform a geocoding query or search for places via the Geoapify API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Geoapify API key immediately."
  },
  "Geocode": {
    "service": "Geocode API",
    "category": "Geolocation Services",
    "impact": "Unauthorized access to geolocation services, potentially leading to excessive API usage charges or data scraping of address-to-coordinate mapping data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Geocode API key.\n2. Use the key to convert an address to coordinates or vice versa via a Geocoding API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Geocode API key immediately."
  },
  "Geocodify": {
    "service": "Geocodify",
    "category": "Geocoding",
    "impact": "Unauthorized access to geocoding and reverse geocoding capabilities, potentially leading to excessive API usage charges or data scraping of address-to-coordinate mapping data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Geocodify API key.\n2. Use the key to perform a geocoding or reverse geocoding query via the Geocodify API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Geocodify API key immediately."
  },
  "Geocodio": {
    "service": "Geocodio",
    "category": "Geocoding",
    "impact": "Unauthorized access to geocoding and reverse geocoding services, potentially leading to excessive API usage charges or data scraping of address-to-coordinate mapping data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Geocodio API key.\n2. Use the key to convert an address to coordinates or vice versa via the Geocodio API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Geocodio API key immediately."
  },
  "GetGeoAPI": {
    "service": "GetGeoAPI",
    "category": "Geolocation & Currency Conversion",
    "impact": "Unauthorized access to geolocation and currency conversion services, potentially leading to excessive API usage charges or data scraping of location/financial information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed GetGeoAPI keys.\n2. Use the keys to fetch geolocation data or perform currency conversion via the GetGeoAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the GetGeoAPI keys immediately."
  },
  "GetSandbox": {
    "service": "GetSandbox",
    "category": "Sandbox Management",
    "impact": "Unauthorized access to and control over sandboxes, potentially leading to resource abuse, exposure of sensitive testing environments, or injection of malicious code into sandboxed applications.",
    "severity": "High",
    "poc_template": "1. Locate exposed GetSandbox API key.\n2. Attempt to list or manage sandboxes using the GetSandbox API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the GetSandbox API key immediately."
  },
  "Getgist": {
    "service": "Getgist",
    "category": "Contact & Communication Management",
    "impact": "Unauthorized access to and management of contact data and communication settings, potentially leading to data breaches, unauthorized messaging, or exposure of sensitive customer interactions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Getgist API key.\n2. Attempt to list or modify contacts or communication settings using the Getgist API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Getgist API key immediately."
  },
  "Getresponse": {
    "service": "GetResponse",
    "category": "Email Marketing",
    "impact": "Unauthorized access to and management of email marketing campaigns, contacts, and other related data, potentially leading to unauthorized email sending, spamming, or exposure of sensitive subscriber data.",
    "severity": "High",
    "poc_template": "1. Locate exposed GetResponse API key.\n2. Attempt to list contacts or send a test email campaign using the GetResponse API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the GetResponse API key immediately."
  },
  "GitHubApp": {
    "service": "GitHub",
    "category": "Version Control & Collaboration",
    "impact": "Unauthorized authentication and interaction with the GitHub API on behalf of the application, potentially leading to access to private repositories, code injection, or manipulation of project workflows depending on the app's permissions.",
    "severity": "High",
    "poc_template": "1. Locate exposed GitHub App keys (e.g., private key and app ID).\n2. Attempt to generate an installation access token using the found credentials.\n3. Use the access token to list repositories or perform actions on behalf of the app.",
    "remediation": "Revoke the exposed GitHub App private key and regenerate it. Review the app's permissions and audit logs for unauthorized activities."
  },
  "GitHubOauth2": {
    "service": "GitHub",
    "category": "Version Control & Collaboration",
    "impact": "Unauthorized authentication and authorization to access GitHub's API on behalf of a user or organization, potentially leading to access to private repositories, code injection, or sensitive data exposure depending on the scope granted by the OAuth token.",
    "severity": "High",
    "poc_template": "1. Locate exposed GitHub OAuth2 credentials (client ID and client secret).\n2. Attempt to use these credentials to initiate an OAuth flow to obtain an access token.\n3. If successful, use the access token to query user data or repositories.",
    "remediation": "Revoke the exposed GitHub OAuth2 client secret immediately. Review the OAuth application's permissions and audit logs for unauthorized activities."
  },
  "Github": {
    "service": "GitHub",
    "category": "Version Control & Collaboration",
    "impact": "Unauthorized access to and modification of repositories and other resources, potentially leading to intellectual property theft, code injection, or disruption of software development workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed GitHub Personal Access Token (PAT).\n2. Configure Git or GitHub CLI with the found PAT.\n3. Attempt to list private repositories or clone a repository.\n4. Verify successful access and resource enumeration.",
    "remediation": "Immediately revoke the exposed GitHub Personal Access Token and generate a new one, ensuring it has minimal necessary permissions and a short lifespan."
  },
  "Gitlab": {
    "service": "GitLab",
    "category": "DevOps Lifecycle Tool",
    "impact": "Unauthorized authentication and access to GitLab resources, including private repositories, issue tracking, and CI/CD pipelines, potentially leading to intellectual property theft, code injection, or disruption of DevOps workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed GitLab Personal Access Token (PAT).\n2. Configure Git or GitLab CLI with the found PAT.\n3. Attempt to list private projects, access issues, or trigger CI/CD pipelines.\n4. Verify successful access and resource enumeration.",
    "remediation": "Immediately revoke the exposed GitLab Personal Access Token and generate a new one, ensuring it has minimal necessary permissions and a short lifespan."
  },
  "Gitter": {
    "service": "Gitter",
    "category": "Chat & Networking",
    "impact": "Unauthorized access to and interaction with Gitter services and data, potentially leading to unauthorized messaging, eavesdropping on private conversations, or account impersonation.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Gitter API key.\n2. Attempt to list rooms or send a message to a public room using the Gitter API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Gitter API key immediately."
  },
  "Glassnode": {
    "service": "Glassnode",
    "category": "On-chain Market Intelligence",
    "impact": "Unauthorized access to various blockchain metrics and data points, potentially leading to data scraping or misuse of cryptocurrency market intelligence.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Glassnode API key.\n2. Use the key to fetch blockchain data or metrics via the Glassnode API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Glassnode API key immediately."
  },
  "GoCanvas": {
    "service": "GoCanvas",
    "category": "Business Process Automation",
    "impact": "Unauthorized access to and modification of data within the GoCanvas platform, potentially leading to data breaches, form manipulation, or disruption of automated business processes.",
    "severity": "High",
    "poc_template": "1. Locate exposed GoCanvas API key.\n2. Attempt to list or modify data collected through mobile forms using the GoCanvas API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the GoCanvas API key immediately."
  },
  "GoCardless": {
    "service": "GoCardless",
    "category": "Online Payments",
    "impact": "Unauthorized access to and management of payment transactions, potentially leading to financial fraud, unauthorized direct debit collection, or exposure of sensitive payment information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed GoCardless API keys.\n2. Attempt to retrieve payment mandates or initiate a payment using the GoCardless API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke and regenerate the GoCardless API keys. Review all transaction logs for unauthorized activity."
  },
  "GoDaddy": {
    "service": "GoDaddy",
    "category": "Domain & Hosting Services",
    "impact": "Unauthorized access to website building, hosting, and security tools, potentially leading to website defacement, domain hijacking, DNS manipulation, or access to sensitive customer data, severely impacting online presence and security.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed GoDaddy API keys/credentials.\n2. Attempt to access or modify domain settings, hosting configurations, or DNS records via the GoDaddy API.\n3. Verify successful administrative access and resource manipulation.",
    "remediation": "Immediately revoke the exposed GoDaddy API keys/credentials and generate new ones. Implement strong access controls and multi-factor authentication for GoDaddy accounts. Review all account activity for unauthorized changes."
  },
  "GoodDay": {
    "service": "GoodDay",
    "category": "Project Management",
    "impact": "Unauthorized access to and management of project data, potentially leading to project disruption, data theft, or exposure of sensitive project details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed GoodDay API token.\n2. Attempt to list or modify project tasks using the GoodDay API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the GoodDay API token immediately."
  },
  "GoogleOauth2": {
    "service": "Google",
    "category": "Authentication & Authorization",
    "impact": "Unauthorized authentication and authorization to access Google APIs and services on behalf of a user, potentially leading to data exfiltration from Google Drive, Gmail, Calendar, or other Google services, depending on the granted scopes.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Google OAuth 2.0 tokens (access token or refresh token).\n2. Use the token to make an API request to a Google service (e.g., list files in Google Drive, read Gmail messages).\n3. Verify successful data access.",
    "remediation": "Invalidate the exposed Google OAuth 2.0 token through Google's security settings (e.g., revoking application access). Advise affected users to review their connected applications."
  },
  "Grafana": {
    "service": "Grafana",
    "category": "Monitoring & Observability",
    "impact": "Unauthorized access to and management of Grafana resources, including dashboards, data sources, and alerts, potentially leading to exposure of sensitive metrics, data manipulation, or disruption of monitoring systems.",
    "severity": "High",
    "poc_template": "1. Locate exposed Grafana API key.\n2. Attempt to list dashboards or create a new data source using the Grafana API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Grafana API key immediately."
  },
  "GrafanaServiceAccount": {
    "service": "Grafana",
    "category": "Monitoring & Observability",
    "impact": "Unauthorized authentication and interaction with Grafana's API, potentially leading to full control over dashboards, data sources, and alerts, allowing for data manipulation, exposure of sensitive metrics, or disruption of monitoring systems.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Grafana service account credentials.\n2. Attempt to list all dashboards, modify a data source, or create new alerts using the Grafana API with the found credentials.\n3. Verify successful administrative action.",
    "remediation": "Immediately revoke the exposed Grafana service account credentials and generate new ones with minimal necessary permissions. Review Grafana audit logs for any unauthorized changes."
  },
  "GraphCMS": {
    "service": "GraphCMS (Hygraph)",
    "category": "Headless CMS",
    "impact": "Unauthorized interaction with CMS content, potentially leading to unauthorized content publishing, content manipulation, or deletion of crucial digital content.",
    "severity": "High",
    "poc_template": "1. Locate exposed GraphCMS API token.\n2. Attempt to retrieve or modify content entries via the GraphCMS API with the found token.\n3. Verify successful content manipulation.",
    "remediation": "Revoke the GraphCMS API token immediately and generate a new one, storing it securely."
  },
  "Graphhopper": {
    "service": "Graphhopper",
    "category": "Routing Engine",
    "impact": "Unauthorized access to and utilization of routing services, potentially leading to excessive API usage charges or the exploitation of navigation data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Graphhopper API key.\n2. Use the key to plan a route via the Graphhopper API.\n3. Verify successful route calculation.",
    "remediation": "Rotate the Graphhopper API key immediately."
  },
  "Groovehq": {
    "service": "GrooveHQ",
    "category": "Help Desk Software",
    "impact": "Unauthorized access to and management of support tickets and customer interactions, potentially leading to data breaches, support ticket manipulation, or exposure of sensitive customer service data.",
    "severity": "High",
    "poc_template": "1. Locate exposed GrooveHQ API key.\n2. Attempt to list tickets or retrieve customer interactions using the GrooveHQ API with the found key.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the GrooveHQ API key immediately."
  },
  "Groq": {
    "service": "Groq",
    "category": "AI Hardware & Software",
    "impact": "Unauthorized access to and usage of Groq's AI services, potentially leading to resource abuse, generation of harmful content, or exposure of proprietary AI interactions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Groq API key.\n2. Attempt to make a request to a Groq service (e.g., run a language model) using the found key.\n3. Verify successful API interaction and response.",
    "remediation": "Revoke and regenerate the Groq API key immediately."
  },
  "Guardianapi": {
    "service": "The Guardian API",
    "category": "News & Content",
    "impact": "Unauthorized access to content and data from The Guardian's API, potentially leading to excessive API usage charges or data scraping of news articles and content.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Guardian API key.\n2. Use the key to retrieve articles or search content via The Guardian's API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate The Guardian API key immediately."
  },
  "Gumroad": {
    "service": "Gumroad",
    "category": "E-commerce Platform (Creators)",
    "impact": "Unauthorized access to and management of products by creators, potentially leading to unauthorized product modification, pricing changes, or access to sales data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Gumroad API key.\n2. Attempt to list or modify products using the Gumroad API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Gumroad API key immediately."
  },
  "Gyazo": {
    "service": "Gyazo",
    "category": "Image Sharing",
    "impact": "Unauthorized access to and management of images stored in a Gyazo account, potentially leading to unauthorized image deletion, exposure of private images, or content manipulation.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Gyazo access token.\n2. Attempt to list or delete images from a Gyazo account using the Gyazo API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the Gyazo access token immediately and generate a new one."
  },
  "Happyscribe": {
    "service": "Happyscribe",
    "category": "Transcription Service",
    "impact": "Unauthorized access to and management of transcription services, potentially leading to excessive API usage charges or the transcription of sensitive audio without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Happyscribe API key.\n2. Attempt to submit an audio file for transcription using the Happyscribe API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Happyscribe API key immediately."
  },
  "Harness": {
    "service": "Harness.io",
    "category": "AI-driven CI/CD Platform",
    "impact": "Unauthorized access to and management of CI/CD pipelines, potentially leading to unauthorized software deployments, injection of malicious code into releases, or disruption of software delivery workflows. Full control over build, test, and deployment processes.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Harness.io credentials (API keys/tokens).\n2. Attempt to list pipelines, trigger deployments, or access build artifacts via the Harness.io API.\n3. Verify successful administrative access and resource manipulation.",
    "remediation": "Immediately revoke the exposed Harness.io credentials and generate new ones. Implement strong access controls and multi-factor authentication. Review all audit logs for unauthorized activities."
  },
  "Harvest": {
    "service": "Harvest",
    "category": "Time Tracking & Invoicing",
    "impact": "Unauthorized access to and management of time tracking data and invoices, potentially leading to inaccurate billing, financial fraud, or exposure of sensitive project and client financial details.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Harvest API key.\n2. Attempt to retrieve or modify time entries or invoices using the Harvest API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Harvest API key immediately."
  },
  "HelloSign": {
    "service": "HelloSign",
    "category": "eSignature Provider",
    "impact": "Unauthorized interaction with the HelloSign API, allowing for the management and sending of documents for eSignature, potentially leading to unauthorized document signing, tampering with contracts, or exposure of sensitive document content.",
    "severity": "High",
    "poc_template": "1. Locate exposed HelloSign API key.\n2. Attempt to list signature requests or send a test document for signing using the HelloSign API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the HelloSign API key immediately."
  },
  "HelpCrunch": {
    "service": "HelpCrunch",
    "category": "Customer Communication Platform",
    "impact": "Unauthorized access to and management of customer interactions and data (live chat, email automation), potentially leading to unauthorized communication, privacy breaches, or exposure of sensitive customer support details.",
    "severity": "High",
    "poc_template": "1. Locate exposed HelpCrunch API key.\n2. Attempt to list conversations or send a message using the HelpCrunch API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the HelpCrunch API key immediately."
  },
  "Helpscout": {
    "service": "Helpscout",
    "category": "Customer Service Software",
    "impact": "Unauthorized access to and management of customer interactions and data in the help desk, potentially leading to data breaches, support ticket manipulation, or exposure of sensitive customer service details.",
    "severity": "High",
    "poc_template": "1. Locate exposed Helpscout API key.\n2. Attempt to list conversations or retrieve customer data using the Helpscout API with the found key.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Helpscout API key immediately."
  },
  "HereAPI": {
    "service": "HereAPI",
    "category": "Location-based Services",
    "impact": "Unauthorized access to a wide range of location-based services (maps, geocoding, traffic), potentially leading to excessive API usage charges or data scraping of sensitive location information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed HereAPI key.\n2. Use the key to query map data, perform a geocoding lookup, or retrieve traffic information via the HereAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the HereAPI key immediately."
  },
  "Heroku": {
    "service": "Heroku",
    "category": "Cloud Platform",
    "impact": "Unauthorized access to and management of Heroku applications and services, potentially leading to unauthorized code deployments, data exfiltration from databases, or denial of service for hosted applications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Heroku API key.\n2. Configure Heroku CLI with the found key.\n3. Attempt to list applications, access environment variables, or deploy code.\n4. Verify successful access and resource manipulation.",
    "remediation": "Immediately revoke the exposed Heroku API key and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Hiveage": {
    "service": "Hiveage",
    "category": "Online Invoicing & Billing",
    "impact": "Unauthorized access to and management of invoicing and billing data, potentially leading to financial fraud, data manipulation, or exposure of sensitive financial records.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Hiveage API key.\n2. Attempt to retrieve or modify invoice data or client information using the Hiveage API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Hiveage API key immediately."
  },
  "HolidayAPI": {
    "service": "HolidayAPI",
    "category": "Holiday Data",
    "impact": "Unauthorized access to holiday data for various countries and years, potentially leading to excessive API usage charges or data scraping of public holiday schedules.",
    "severity": "Low",
    "poc_template": "1. Locate exposed HolidayAPI key.\n2. Use the key to fetch holiday data for a specific country/year via the HolidayAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the HolidayAPI key immediately."
  },
  "Holistic": {
    "service": "Holistic",
    "category": "Project Management",
    "impact": "Unauthorized access to and management of comprehensive project management solutions, potentially leading to project disruption, data theft, or exposure of sensitive project details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Holistic API key.\n2. Attempt to list or modify project data using the Holistic API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Holistic API key immediately."
  },
  "Honeycomb": {
    "service": "Honeycomb",
    "category": "Observability Platform",
    "impact": "Unauthorized authentication and interaction with the Honeycomb API, potentially leading to access to sensitive production system data, injection of false telemetry, or disruption of observability insights.",
    "severity": "High",
    "poc_template": "1. Locate exposed Honeycomb API key.\n2. Attempt to query existing datasets or send new events using the Honeycomb API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Honeycomb API key immediately."
  },
  "Host": {
    "service": "Host.io",
    "category": "Domain Data",
    "impact": "Unauthorized access to and management of domain data and related services, potentially leading to data scraping of domain information or misuse of reconnaissance tools.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Host.io token.\n2. Use the token to query domain information via the Host.io API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Host.io token immediately."
  },
  "Html2Pdf": {
    "service": "Html2Pdf",
    "category": "HTML to PDF Conversion",
    "impact": "Unauthorized authentication and authorization to convert HTML content into PDF documents, potentially leading to excessive API usage charges or the generation of unauthorized PDF documents from sensitive HTML.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Html2Pdf API key.\n2. Attempt to convert HTML content to a PDF document using the Html2Pdf API with the found key.\n3. Verify successful PDF generation.",
    "remediation": "Rotate the Html2Pdf API key immediately."
  },
  "HubSpotApiKey": {
    "service": "HubSpot",
    "category": "CRM Platform",
    "impact": "Unauthorized access to and modification of data within the HubSpot platform, including marketing, sales, and customer service data, potentially leading to data breaches, lead manipulation, or disruption of customer relationships.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed HubSpot API key.\n2. Attempt to retrieve or modify contact data, deals, or marketing campaigns using the HubSpot API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the HubSpot API key immediately."
  },
  "HuggingFace": {
    "service": "Hugging Face",
    "category": "NLP & AI Model Hosting",
    "impact": "Unauthorized access to various services and resources on the Hugging Face platform, including natural language processing tasks and model hosting, potentially leading to resource abuse, exposure of proprietary models, or unauthorized execution of AI tasks.",
    "severity": "High",
    "poc_template": "1. Locate exposed Hugging Face API key.\n2. Attempt to interact with a model (e.g., run inference) or access datasets/models using the Hugging Face API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Hugging Face API key immediately."
  },
  "Humanity": {
    "service": "Humanity",
    "category": "Workforce Management",
    "impact": "Unauthorized access to and management of workforce data and operations, including scheduling, time tracking, and payroll-related information, potentially leading to payroll fraud, disruption of operations, or exposure of sensitive employee information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Humanity API key.\n2. Attempt to retrieve or modify employee schedules or time entries using the Humanity API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Humanity API key immediately."
  },
  "Hunter": {
    "service": "Hunter",
    "category": "Email Verification & Discovery",
    "impact": "Unauthorized access to and retrieval of professional email addresses and verification services, potentially leading to excessive API usage charges or data scraping for lead generation.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Hunter API key.\n2. Use the key to find email addresses for a domain or verify an email address via the Hunter API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Hunter API key immediately."
  },
  "Hybiscus": {
    "service": "Hybiscus",
    "category": "API Service",
    "impact": "Unauthorized access to Hybiscus resources and performance of operations, potentially leading to resource abuse, data breaches, or disruption of services, depending on the service's functionality.",
    "severity": "High",
    "poc_template": "1. Locate exposed Hybiscus API key.\n2. Attempt to access or modify data/resources using the Hybiscus API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Hybiscus API key and generate a new one immediately."
  },
  "Hypertrack": {
    "service": "Hypertrack",
    "category": "Live Location Tracking",
    "impact": "Unauthorized access to and management of live location tracking services, potentially leading to privacy breaches, unauthorized tracking of fleets/mobile workforce, or exposure of sensitive movement data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Hypertrack keys.\n2. Attempt to retrieve live location data for devices or manage tracking sessions using the Hypertrack API with the found keys.\n3. Verify successful data access and control.",
    "remediation": "Revoke and regenerate the Hypertrack keys immediately."
  },
  "IPGeolocation": {
    "service": "IPGeolocation",
    "category": "Geolocation",
    "impact": "Unauthorized access to geolocation information about IP addresses, potentially leading to excessive API usage charges or data scraping of location data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed IPGeolocation API key.\n2. Use the key to retrieve geolocation data for an IP address via the IPGeolocation API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the IPGeolocation API key immediately."
  },
  "IPQuality": {
    "service": "IPQualityScore",
    "category": "Fraud Prevention",
    "impact": "Unauthorized access to fraud detection and prevention services, potentially leading to resource abuse, bypassing security checks, or injection of false fraud reports.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed IPQualityScore API key.\n2. Attempt to check an IP address for fraudulent activity using the IPQualityScore API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the IPQualityScore API key immediately."
  },
  "IPinfoDB": {
    "service": "IPinfoDB",
    "category": "IP Geolocation",
    "impact": "Unauthorized access to IP address geolocation services, potentially leading to excessive API usage charges or data scraping of location data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed IPinfoDB API key.\n2. Use the key to retrieve geolocation data for an IP address via the IPinfoDB API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the IPinfoDB API key immediately."
  },
  "IconFinder": {
    "service": "IconFinder",
    "category": "Icon Library",
    "impact": "Unauthorized access to and retrieval of icons from the platform, potentially leading to excessive API usage charges or data scraping of proprietary icon designs.",
    "severity": "Low",
    "poc_template": "1. Locate exposed IconFinder API key.\n2. Use the key to search for icons or retrieve icon details via the IconFinder API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the IconFinder API key immediately."
  },
  "Iexapis": {
    "service": "IEX Cloud",
    "category": "Financial Market Data",
    "impact": "Unauthorized access to and retrieval of financial market data, potentially leading to excessive API usage charges or data scraping of sensitive financial information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed IEX Cloud API key.\n2. Use the key to fetch financial data (e.g., stock quotes) via the IEX Cloud API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the IEX Cloud API key immediately."
  },
  "Iexcloud": {
    "service": "IEX Cloud",
    "category": "Financial Data Platform",
    "impact": "Unauthorized access to and retrieval of a wide range of financial data APIs, potentially leading to excessive API usage charges or data scraping of sensitive financial information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed IEX Cloud token.\n2. Use the token to fetch financial data (e.g., company financials, stock prices) via the IEX Cloud API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the IEX Cloud token immediately."
  },
  "Imagekit": {
    "service": "Imagekit",
    "category": "Image Optimization & Transformation",
    "impact": "Unauthorized access to and manipulation of images on the platform, potentially leading to image manipulation, unauthorized image delivery, or disruption of content presentation.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Imagekit keys.\n2. Attempt to optimize or transform an image using the Imagekit API with the found keys.\n3. Verify successful image processing.",
    "remediation": "Rotate the Imagekit keys immediately."
  },
  "Imagga": {
    "service": "Imagga",
    "category": "Image Recognition & Categorization",
    "impact": "Unauthorized access to and utilization of image recognition and categorization services, potentially leading to excessive API usage charges or the processing of sensitive image data without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Imagga API key.\n2. Attempt to upload an image for tagging or categorization using the Imagga API with the found key.\n3. Verify successful image analysis.",
    "remediation": "Rotate the Imagga API key immediately."
  },
  "Impala": {
    "service": "Impala",
    "category": "Travel API",
    "impact": "Unauthorized access to and modification of booking and reservation data, potentially leading to booking manipulation, access to traveler information, or fraud.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Impala API key.\n2. Attempt to search for bookings or modify reservation data using the Impala API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Impala API key immediately."
  },
  "Infura": {
    "service": "Infura",
    "category": "Blockchain Infrastructure",
    "impact": "Unauthorized interaction with the Ethereum blockchain infrastructure, potentially leading to resource abuse (e.g., excessive API calls), monitoring of on-chain activity, or unauthorized transaction submissions if the key has write permissions.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Infura key.\n2. Use the key to make a request to an Ethereum node (e.g., get latest block number) via the Infura API.\n3. Verify successful connection to the Ethereum network.",
    "remediation": "Rotate the Infura key immediately. If the key has write access, verify no unauthorized transactions were made."
  },
  "Insightly": {
    "service": "Insightly",
    "category": "Customer Relationship Management (CRM)",
    "impact": "Unauthorized access to and management of CRM data, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "High",
    "poc_template": "1. Locate exposed Insightly API key.\n2. Attempt to list or modify CRM data (e.g., contacts, opportunities) using the Insightly API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Insightly API key immediately."
  },
  "Instabot": {
    "service": "Instabot",
    "category": "Social Media Automation",
    "impact": "Unauthorized access to and interaction with automated social media services, potentially leading to unauthorized posting, account impersonation, or resource abuse.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Instabot API key.\n2. Attempt to perform an action (e.g., send a message, like a post) via the Instabot API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Instabot API key immediately."
  },
  "Instamojo": {
    "service": "Instamojo",
    "category": "Ecommerce Service",
    "impact": "Unauthorized creation and access to customer data, potentially leading to financial fraud, customer data theft, or unauthorized product management.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Instamojo API keys.\n2. Attempt to create a test order or retrieve customer data using the Instamojo API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke and regenerate the Instamojo API keys. Review all transaction logs for unauthorized activity."
  },
  "Intercom": {
    "service": "Intercom",
    "category": "Customer Messaging",
    "impact": "Unauthorized access to and management of customer data and communication, potentially leading to unauthorized messaging, privacy breaches, or exposure of sensitive customer interactions.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Intercom tokens.\n2. Attempt to list users, read conversations, or send messages using the Intercom API with the found tokens.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Intercom tokens immediately and generate new ones."
  },
  "Interseller": {
    "service": "Interseller",
    "category": "Email Outreach Automation",
    "impact": "Unauthorized management and sending of email campaigns, potentially leading to unauthorized email outreach, spamming, or exposure of sensitive sales leads.",
    "severity": "High",
    "poc_template": "1. Locate exposed Interseller API key.\n2. Attempt to list campaigns or send a test email using the Interseller API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Interseller API key immediately."
  },
  "Intra42": {
    "service": "Intra42",
    "category": "Educational Platform API",
    "impact": "Unauthorized access to and modification of data within the 42 school's internal systems, potentially leading to unauthorized access to student information, academic records, or system manipulation.",
    "severity": "High",
    "poc_template": "1. Locate exposed Intra42 API key.\n2. Attempt to query student data or modify system settings using the Intra42 API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Intra42 API key immediately."
  },
  "Intrinio": {
    "service": "Intrinio",
    "category": "Financial Data APIs",
    "impact": "Unauthorized access to various financial datasets and services, potentially leading to excessive API usage charges or data scraping of sensitive financial information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Intrinio API key.\n2. Use the key to fetch financial data (e.g., stock prices, company fundamentals) via the Intrinio API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Intrinio API key immediately."
  },
  "InvoiceOcean": {
    "service": "InvoiceOcean",
    "category": "Online Invoicing Service",
    "impact": "Unauthorized access to and management of invoices and other financial data, potentially leading to financial fraud, data manipulation, or exposure of sensitive billing information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed InvoiceOcean API token.\n2. Attempt to retrieve or modify invoice data or client information using the InvoiceOcean API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the InvoiceOcean API token immediately."
  },
  "Ip2location": {
    "service": "Ip2location",
    "category": "IP Geolocation",
    "impact": "Unauthorized access to IP geolocation data, potentially leading to excessive API usage charges or data scraping of location information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Ip2location keys.\n2. Use the keys to retrieve geolocation data for an IP address via the Ip2location API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Ip2location keys immediately."
  },
  "IpStack": {
    "service": "IpStack",
    "category": "IP Geolocation",
    "impact": "Unauthorized access to IP geolocation services, potentially leading to excessive API usage charges or data scraping of location data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed IpStack API key.\n2. Use the key to retrieve geolocation data for an IP address via the IpStack API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the IpStack API key immediately."
  },
  "Ipapi": {
    "service": "Ipapi",
    "category": "IP Address Lookup & Geolocation",
    "impact": "Unauthorized access to IP address lookup and geolocation services, potentially leading to excessive API usage charges or data scraping of location information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Ipapi keys.\n2. Use the keys to retrieve geolocation data for an IP address via the Ipapi API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Ipapi keys immediately."
  },
  "JDBC": {
    "service": "JDBC (Java Database Connectivity)",
    "category": "Database Access",
    "impact": "Unauthorized access to and manipulation of databases, potentially leading to complete data compromise, data exfiltration, injection of malicious queries, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed JDBC connection string (containing username/password/host).\n2. Attempt to connect to the database using a JDBC client or a tool like DbVisualizer with the found credentials.\n3. Verify successful connection and attempt to query/modify sensitive data.",
    "remediation": "Immediately rotate database credentials and ensure JDBC connection strings are not exposed. Implement strong access controls, network segmentation, and encryption for database connections."
  },
  "JiraToken": {
    "service": "Jira",
    "category": "Issue Tracking & Project Management",
    "impact": "Unauthorized authentication and access to Jira, potentially leading to viewing, modifying, or deleting issues, projects, and other sensitive project management data, disrupting workflows or exposing confidential project details.",
    "severity": "High",
    "poc_template": "1. Locate exposed Jira token.\n2. Attempt to list issues, modify a task, or access project boards using the Jira API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Jira token immediately and generate a new one, ensuring it has minimal necessary permissions and a short lifespan."
  },
  "Jotform": {
    "service": "Jotform",
    "category": "Online Form Builder",
    "impact": "Unauthorized access to and management of form submissions and data, potentially leading to data theft, form manipulation, or exposure of sensitive information collected through forms.",
    "severity": "High",
    "poc_template": "1. Locate exposed Jotform API key.\n2. Attempt to list forms or retrieve data submissions using the Jotform API with the found key.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Jotform API key immediately."
  },
  "Jumpcloud": {
    "service": "Jumpcloud",
    "category": "Cloud Directory Service",
    "impact": "Unauthorized access to and management of user and device management, single sign-on, and other IAM features, potentially leading to unauthorized user creation, privilege escalation, or system compromise across an organization's IT infrastructure.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Jumpcloud API key.\n2. Attempt to list users, modify user attributes, or manage devices using the Jumpcloud API with the found key.\n3. Verify successful administrative action.",
    "remediation": "Revoke and regenerate the Jumpcloud API key immediately. Review Jumpcloud audit logs for any unauthorized activities."
  },
  "JupiterOne": {
    "service": "JupiterOne",
    "category": "Cloud Security Management",
    "impact": "Unauthorized access to and management of security data, potentially leading to exposure of sensitive security configurations, vulnerability information, or asset inventory.",
    "severity": "High",
    "poc_template": "1. Locate exposed JupiterOne API key.\n2. Attempt to query security data or list assets using the JupiterOne API with the found key.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the JupiterOne API key immediately."
  },
  "Juro": {
    "service": "Juro",
    "category": "Contract Automation",
    "impact": "Unauthorized access to and management of contract templates and other resources, potentially leading to intellectual property theft, contract tampering, or exposure of sensitive legal documents.",
    "severity": "High",
    "poc_template": "1. Locate exposed Juro API key.\n2. Attempt to list templates or create/modify contracts using the Juro API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Juro API key immediately."
  },
  "Kanban": {
    "service": "KanbanTool",
    "category": "Project Management Software",
    "impact": "Unauthorized access to and modification of project data, potentially leading to project disruption, data theft, or exposure of sensitive task details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Kanban API key.\n2. Attempt to list or modify project boards/tasks using the Kanban API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Kanban API key immediately."
  },
  "Kanbantool": {
    "service": "KanbanTool",
    "category": "Project Management Software",
    "impact": "Unauthorized access to and modification of project data, potentially leading to project disruption, data theft, or exposure of sensitive task details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Kanbantool API key.\n2. Attempt to list or modify project boards/tasks using the Kanbantool API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Kanbantool API key immediately."
  },
  "KarmaCRM": {
    "service": "KarmaCRM",
    "category": "Customer Relationship Management (CRM)",
    "impact": "Unauthorized access to and modification of CRM data, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "High",
    "poc_template": "1. Locate exposed KarmaCRM API token.\n2. Attempt to list or modify CRM data (e.g., contacts, deals) using the KarmaCRM API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the KarmaCRM API token immediately."
  },
  "KeenIO": {
    "service": "KeenIO",
    "category": "Analytics Platform",
    "impact": "Unauthorized access to and management of event data, potentially leading to injection of false analytics, data exfiltration of sensitive event information, or disruption of data visualization.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed KeenIO API key.\n2. Attempt to query event data or send new events to a collection using the KeenIO API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the KeenIO API key immediately."
  },
  "Kickbox": {
    "service": "Kickbox",
    "category": "Email Verification",
    "impact": "Unauthorized access to and utilization of email verification services, potentially leading to excessive API usage charges or the verification of large email lists for spamming or phishing purposes.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Kickbox API key.\n2. Use the key to verify an email address via the Kickbox API.\n3. Verify successful verification result.",
    "remediation": "Rotate the Kickbox API key immediately."
  },
  "Klaviyo": {
    "service": "Klaviyo",
    "category": "Marketing Automation",
    "impact": "Unauthorized access to and modification of marketing data and configurations, including customer profiles, email campaigns, and analytics, potentially leading to unauthorized email sending, data breaches, or disruption of marketing efforts.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Klaviyo API key.\n2. Attempt to list customer profiles, send a test campaign, or modify marketing flows using the Klaviyo API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Klaviyo API key immediately."
  },
  "Klipfolio": {
    "service": "Klipfolio",
    "category": "Business Intelligence",
    "impact": "Unauthorized access to and management of dashboards and reporting tools, potentially leading to exposure of sensitive business metrics, data manipulation, or disruption of data visualization.",
    "severity": "High",
    "poc_template": "1. Locate exposed Klipfolio API key.\n2. Attempt to list dashboards or modify data sources using the Klipfolio API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Klipfolio API key immediately."
  },
  "KnapsackPro": {
    "service": "KnapsackPro",
    "category": "Test Suite Parallelization",
    "impact": "Unauthorized access to and management of test suite runs and configurations, potentially leading to the injection of false test results, disruption of testing pipelines, or exposure of sensitive test data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed KnapsackPro token.\n2. Attempt to list test suite runs or modify configurations using the KnapsackPro API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Rotate the KnapsackPro token immediately."
  },
  "Kontent": {
    "service": "Kontent",
    "category": "Headless CMS",
    "impact": "Unauthorized access to and management of content, potentially leading to unauthorized content publishing, content manipulation, or deletion of crucial digital content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Kontent API key.\n2. Attempt to retrieve or modify content entries via the Kontent API with the found key.\n3. Verify successful content manipulation.",
    "remediation": "Revoke the Kontent API key immediately and generate a new one, storing it securely."
  },
  "Kraken": {
    "service": "Kraken",
    "category": "Cryptocurrency Exchange",
    "impact": "Unauthorized access to and management of account information and performance of trading operations, potentially leading to unauthorized cryptocurrency trades, fund transfers, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Kraken API keys.\n2. Attempt to retrieve account balance or place an order using the Kraken API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Kraken API keys immediately and enable appropriate security measures like API key permissions and IP whitelisting."
  },
  "KuCoin": {
    "service": "KuCoin",
    "category": "Cryptocurrency Exchange",
    "impact": "Unauthorized access to and management of trading accounts, execution of trades, and retrieval of market data, potentially leading to unauthorized cryptocurrency trades, fund manipulation, or exposure of sensitive trading history.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed KuCoin API keys.\n2. Attempt to retrieve account balance or place an order using the KuCoin API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the KuCoin API keys immediately and enable appropriate security measures like IP whitelisting."
  },
  "Kylas": {
    "service": "Kylas",
    "category": "Sales CRM Platform",
    "impact": "Unauthorized access to and management of sales data, potentially leading to data breaches, lead manipulation, or exposure of sensitive sales strategies and customer information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Kylas API key.\n2. Attempt to list or modify sales leads or opportunities using the Kylas API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Kylas API key immediately."
  }
}





































{
  "LDAP": {
    "service": "LDAP (Lightweight Directory Access Protocol)",
    "category": "Directory Services",
    "impact": "Unauthorized access to and maintenance of distributed directory information services, potentially leading to data exfiltration of user credentials, organizational structure, or sensitive network configurations. Could also enable privilege escalation or impersonation.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed LDAP credentials (username/password) or connection details.\n2. Attempt to bind to the LDAP server using an LDAP client (e.g., ldapsearch, Apache Directory Studio) with the found credentials.\n3. Verify successful connection and attempt to enumerate users, groups, or other directory entries.",
    "remediation": "Immediately rotate LDAP credentials. Implement strong access controls, network segmentation for LDAP servers, and ensure LDAP is not exposed to the internet unnecessarily. Consider using LDAPS for encrypted communication."
  },
  "Langfuse": {
    "service": "Langfuse",
    "category": "AI Application Platform",
    "impact": "Unauthorized access to and usage of Langfuse's platform for building and scaling AI applications, potentially leading to resource abuse, exposure of proprietary AI models, or manipulation of AI application data and configurations.",
    "severity": "High",
    "poc_template": "1. Locate exposed Langfuse API key.\n2. Attempt to interact with Langfuse services (e.g., track traces, manage projects) using the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Langfuse API key immediately."
  },
  "LanguageLayer": {
    "service": "LanguageLayer",
    "category": "Language Detection API",
    "impact": "Unauthorized authentication and usage of the language detection API, potentially leading to excessive API usage charges or the processing of sensitive text for language detection without consent.",
    "severity": "Low",
    "poc_template": "1. Locate exposed LanguageLayer access key.\n2. Use the key to perform a language detection query via the LanguageLayer API.\n3. Verify successful language detection.",
    "remediation": "Rotate the LanguageLayer access key immediately."
  },
  "LarkSuite": {
    "service": "LarkSuite",
    "category": "Collaborative Suite",
    "impact": "Unauthorized access to and interaction with chat, calendar, and cloud storage features, potentially leading to unauthorized communication, data exfiltration from cloud storage, or exposure of sensitive meeting information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed LarkSuite token.\n2. Attempt to list chats, access cloud documents, or view calendar events using the LarkSuite API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed LarkSuite token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "LarkSuiteApiKey": {
    "service": "LarkSuite",
    "category": "Collaboration Platform",
    "impact": "Unauthorized access to and management of communication, calendar, and cloud storage services, potentially leading to unauthorized messaging, data breaches, or manipulation of collaborative workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed LarkSuite API key.\n2. Attempt to list users, access cloud files, or manage calendar events using the LarkSuite API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the LarkSuite API key immediately."
  },
  "LaunchDarkly": {
    "service": "LaunchDarkly",
    "category": "Feature Management",
    "impact": "Unauthorized access to and modification of feature flags and other resources, potentially leading to unauthorized feature rollouts/rollbacks, exposure of sensitive feature configurations, or disruption of application functionality.",
    "severity": "High",
    "poc_template": "1. Locate exposed LaunchDarkly API key.\n2. Attempt to list feature flags or modify a flag's targeting rules using the LaunchDarkly API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the LaunchDarkly API key immediately."
  },
  "Leadfeeder": {
    "service": "Leadfeeder",
    "category": "Website Visitor Identification",
    "impact": "Unauthorized access to and management of website visitor data (companies, how they found the site, their interests), potentially leading to exposure of sensitive sales intelligence or misuse of lead generation data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Leadfeeder API key.\n2. Attempt to retrieve visitor data or company profiles using the Leadfeeder API with the found key.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Leadfeeder API key immediately."
  },
  "Lemlist": {
    "service": "Lemlist",
    "category": "Email Outreach Platform",
    "impact": "Unauthorized access to and management of email campaigns and contacts, potentially leading to unauthorized email sending, spamming, or exposure of sensitive sales leads.",
    "severity": "High",
    "poc_template": "1. Locate exposed Lemlist API key.\n2. Attempt to list campaigns or add a contact using the Lemlist API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Lemlist API key immediately."
  },
  "LemonSqueezy": {
    "service": "LemonSqueezy",
    "category": "Digital Product Sales Platform",
    "impact": "Unauthorized access to manage products, orders, and other resources, potentially leading to unauthorized product manipulation, order theft, or access to sensitive sales and customer data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed LemonSqueezy API token.\n2. Attempt to list products, retrieve order details, or update product information using the LemonSqueezy API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the LemonSqueezy API token immediately."
  },
  "Lendflow": {
    "service": "Lendflow",
    "category": "Financial Data & Services",
    "impact": "Unauthorized access to and manipulation of financial data, potentially leading to financial fraud, data exfiltration, or unauthorized financial transactions.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Lendflow API key.\n2. Attempt to retrieve sensitive financial data or initiate a transaction using the Lendflow API with the found key.\n3. Verify successful data access or transaction initiation.",
    "remediation": "Revoke and regenerate the Lendflow API key immediately. Review all transaction logs for unauthorized activity."
  },
  "LessAnnoyingCRM": {
    "service": "Less Annoying CRM",
    "category": "Customer Relationship Management",
    "impact": "Unauthorized access to and management of customer data, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "High",
    "poc_template": "1. Locate exposed Less Annoying CRM API token.\n2. Attempt to list or modify customer records using the Less Annoying CRM API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Less Annoying CRM API token immediately."
  },
  "Lexigram": {
    "service": "Lexigram",
    "category": "Healthcare Data Service",
    "impact": "Unauthorized access to and retrieval of medical terminology and data, potentially leading to excessive API usage charges or data scraping of sensitive healthcare information.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Lexigram API key.\n2. Use the key to query medical terminology or patient data (if available through the API) via the Lexigram API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Lexigram API key immediately."
  },
  "LineNotify": {
    "service": "LINE Notify",
    "category": "Notification Service",
    "impact": "Unauthorized sending of messages to users or groups, potentially leading to spamming, impersonation, or misuse of the notification service.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Line Notify API key.\n2. Attempt to send a test message to a linked LINE account/group using the Line Notify API with the found key.\n3. Verify successful message delivery.",
    "remediation": "Revoke the exposed Line Notify API key immediately and generate a new one."
  },
  "LinearAPI": {
    "service": "LinearAPI",
    "category": "Project Management Software",
    "impact": "Unauthorized access to and modification of project data, potentially leading to project disruption, data theft, or exposure of sensitive project details.",
    "severity": "High",
    "poc_template": "1. Locate exposed LinearAPI keys.\n2. Attempt to list projects, create issues, or modify tasks using the LinearAPI with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the LinearAPI keys immediately."
  },
  "LinkPreview": {
    "service": "LinkPreview",
    "category": "Web Page Metadata Service",
    "impact": "Unauthorized access to retrieve metadata about web pages, potentially leading to excessive API usage charges or data scraping of link preview information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed LinkPreview API key.\n2. Use the key to retrieve metadata for a URL via the LinkPreview API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the LinkPreview API key immediately."
  },
  "LiveAgent": {
    "service": "LiveAgent",
    "category": "Help Desk Software",
    "impact": "Unauthorized access to various functionalities of the LiveAgent service, potentially leading to access to customer service tickets, customer data, or manipulation of support operations.",
    "severity": "High",
    "poc_template": "1. Locate exposed LiveAgent API key.\n2. Attempt to list tickets or retrieve customer information using the LiveAgent API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the LiveAgent API key immediately."
  },
  "Livestorm": {
    "service": "Livestorm",
    "category": "Video Communication Platform",
    "impact": "Unauthorized interaction with Livestorm services (webinars, meetings, virtual events), potentially leading to unauthorized event creation/modification, access to attendee lists, or disruption of virtual events.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Livestorm API key.\n2. Attempt to list events or register for an event using the Livestorm API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Livestorm API key immediately."
  },
  "Loadmill": {
    "service": "Loadmill",
    "category": "API & Web Application Testing",
    "impact": "Unauthorized access to and management of test scenarios and results, potentially leading to injection of false test data, manipulation of testing processes, or exposure of sensitive application vulnerabilities.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Loadmill API key.\n2. Attempt to list test runs or trigger a new test using the Loadmill API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Loadmill API key immediately."
  },
  "LocationIQ": {
    "service": "LocationIQ",
    "category": "Location-based Services",
    "impact": "Unauthorized access to geocoding and reverse geocoding services, potentially leading to excessive API usage charges or data scraping of location data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed LocationIQ API key.\n2. Use the key to perform a geocoding or reverse geocoding query via the LocationIQ API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the LocationIQ API key immediately."
  },
  "Loggly": {
    "service": "Loggly",
    "category": "Cloud-based Log Management",
    "impact": "Unauthorized access to send, search, and analyze log data, potentially leading to injection of false logs, data exfiltration of sensitive log entries, or disruption of monitoring.",
    "severity": "High",
    "poc_template": "1. Locate exposed Loggly API key.\n2. Attempt to send a test log entry or search existing logs using the Loggly API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Loggly API key immediately."
  },
  "Loginradius": {
    "service": "Loginradius",
    "category": "Customer Identity & Access Management (CIAM)",
    "impact": "Unauthorized management of user identities, authentication, and access control, potentially leading to account takeover, unauthorized access to applications, or exposure of sensitive customer data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Loginradius API keys.\n2. Attempt to list users, modify user profiles, or manage authentication settings using the Loginradius API with the found keys.\n3. Verify successful administrative action.",
    "remediation": "Revoke and regenerate the Loginradius API keys immediately. Review all audit logs for unauthorized activities."
  },
  "LogzIO": {
    "service": "Logz.io",
    "category": "Cloud Observability Platform",
    "impact": "Unauthorized access to and management of log data, potentially leading to injection of false logs, data exfiltration of sensitive log entries, or disruption of monitoring.",
    "severity": "High",
    "poc_template": "1. Locate exposed Logz.io API token.\n2. Attempt to send a test log entry or search existing logs using the Logz.io API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Logz.io API token immediately."
  },
  "LokaliseToken": {
    "service": "Lokalise",
    "category": "Translation Management System",
    "impact": "Unauthorized access to and modification of project data within the translation management system, potentially leading to content tampering, exposure of sensitive translation assets, or disruption of localization workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Lokalise token.\n2. Attempt to list projects, retrieve translation keys, or modify language files using the Lokalise API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Lokalise token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Loyverse": {
    "service": "Loyverse",
    "category": "Point of Sale (POS) System",
    "impact": "Unauthorized access to and modification of sales, inventory, and customer relationships data, potentially leading to financial fraud, inventory manipulation, or exposure of sensitive sales and customer information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Loyverse API keys.\n2. Attempt to retrieve sales reports, modify inventory, or access customer profiles using the Loyverse API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Loyverse API keys immediately. Review all transaction logs for unauthorized activity."
  },
  "LunchMoney": {
    "service": "LunchMoney",
    "category": "Personal Finance Tool",
    "impact": "Unauthorized access to and modification of financial data, potentially leading to financial fraud, unauthorized transaction logging, or exposure of sensitive personal financial information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed LunchMoney API key.\n2. Attempt to retrieve transaction history or add new transactions using the LunchMoney API with the found key.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke and regenerate the LunchMoney API key immediately."
  },
  "Luno": {
    "service": "Luno",
    "category": "Cryptocurrency Exchange",
    "impact": "Unauthorized access to account information and performance of transactions, potentially leading to unauthorized cryptocurrency trades, fund transfers, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Luno API keys.\n2. Attempt to retrieve account balance or initiate a trade using the Luno API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Luno API keys immediately and enable appropriate security measures like IP whitelisting."
  },
  "MadKudu": {
    "service": "MadKudu",
    "category": "Predictive Lead Scoring",
    "impact": "Unauthorized access to and manipulation of lead scoring data, potentially leading to inaccurate lead qualification, manipulation of sales pipelines, or exposure of sensitive sales intelligence.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed MadKudu API key.\n2. Attempt to retrieve lead scores or update lead data using the MadKudu API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the MadKudu API key immediately."
  },
  "MagicBell": {
    "service": "MagicBell",
    "category": "Notification Service",
    "impact": "Unauthorized management and sending of notifications, potentially leading to spamming, impersonation, or misuse of the notification service.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed MagicBell API key.\n2. Attempt to send a test notification or list existing notifications using the MagicBell API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the MagicBell API key immediately."
  },
  "MailJetBasicAuth": {
    "service": "Mailjet",
    "category": "Email Delivery Service",
    "impact": "Unauthorized authentication and sending of emails through the Mailjet API, potentially leading to spamming, phishing attacks, or resource abuse.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Mailjet Basic Auth credentials (API Key and Secret Key).\n2. Attempt to send a test email using the Mailjet SMTP or API with the found credentials.\n3. Verify successful email delivery.",
    "remediation": "Immediately revoke and regenerate the Mailjet API Key and Secret Key. Review Mailjet logs for unauthorized email sending."
  },
  "MailJetSMS": {
    "service": "Mailjet",
    "category": "Cloud-based Email & SMS Service",
    "impact": "Unauthorized sending of SMS messages and management of email campaigns, potentially leading to spamming, phishing attacks via SMS, or exposure of sensitive campaign data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Mailjet API keys.\n2. Attempt to send a test SMS message or list email campaigns using the Mailjet API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Mailjet API keys immediately."
  },
  "Mailboxlayer": {
    "service": "Mailboxlayer",
    "category": "Email Validation & Verification",
    "impact": "Unauthorized validation and verification of email addresses, potentially leading to excessive API usage charges or the misuse of the service for lead generation or spam list validation.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Mailboxlayer API key.\n2. Use the key to validate an email address via the Mailboxlayer API.\n3. Verify successful validation result.",
    "remediation": "Rotate the Mailboxlayer API key immediately."
  },
  "Mailchimp": {
    "service": "Mailchimp",
    "category": "Marketing Automation & Email Marketing",
    "impact": "Unauthorized access to and management of email campaigns, audience data, and other marketing resources, potentially leading to unauthorized email sending, spamming, data breaches of subscriber lists, or manipulation of marketing efforts.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Mailchimp API key.\n2. Attempt to list audiences, send a test campaign, or modify audience data using the Mailchimp API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Mailchimp API key immediately. Review Mailchimp audit logs for any unauthorized activities."
  },
  "Mailerlite": {
    "service": "MailerLite",
    "category": "Email Marketing Service",
    "impact": "Unauthorized access to and modification of email campaign data, potentially leading to unauthorized email sending, spamming, or exposure of sensitive subscriber data.",
    "severity": "High",
    "poc_template": "1. Locate exposed MailerLite API key.\n2. Attempt to list campaigns or add subscribers using the MailerLite API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the MailerLite API key immediately."
  },
  "Mailgun": {
    "service": "Mailgun",
    "category": "Email Automation Service",
    "impact": "Unauthorized sending, receiving, and tracking of emails, potentially leading to spamming, phishing attacks, or unauthorized access to communication data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Mailgun tokens (API key).\n2. Attempt to send a test email via the Mailgun API with the found token.\n3. Verify successful email delivery.",
    "remediation": "Revoke the exposed Mailgun token immediately and generate a new one, ensuring it has minimal necessary permissions (e.g., restricted to sending only if applicable)."
  },
  "Mailmodo": {
    "service": "Mailmodo",
    "category": "Interactive Email Platform",
    "impact": "Unauthorized access to and management of email campaigns and contacts, potentially leading to unauthorized email sending, spamming, or exposure of sensitive campaign data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Mailmodo API key.\n2. Attempt to list campaigns or add contacts using the Mailmodo API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Mailmodo API key immediately."
  },
  "Mailsac": {
    "service": "Mailsac",
    "category": "Disposable Email Service",
    "impact": "Unauthorized access to and management of email addresses and messages, potentially leading to monitoring of test environments, bypassing email verification, or accessing temporary sensitive information.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Mailsac API key.\n2. Attempt to list email addresses or retrieve messages from an inbox using the Mailsac API with the found key.\n3. Verify successful data access.",
    "remediation": "Rotate the Mailsac API key immediately."
  },
  "Mandrill": {
    "service": "Mandrill",
    "category": "Transactional Email API",
    "impact": "Unauthorized sending and tracking of email messages, potentially leading to spamming, phishing attacks, or unauthorized access to communication data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Mandrill API key.\n2. Attempt to send a test transactional email via the Mandrill API with the found key.\n3. Verify successful email delivery.",
    "remediation": "Revoke the exposed Mandrill API key immediately and generate a new one."
  },
  "MapBox": {
    "service": "Mapbox",
    "category": "Location-based Services",
    "impact": "Unauthorized interaction with location-based services and modification of data, potentially leading to excessive API usage charges, map manipulation, or data scraping of sensitive geographic information.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Mapbox access token.\n2. Use the token to access map tiles, perform geocoding, or upload data to a private dataset using the Mapbox API.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Mapbox access token immediately."
  },
  "Mapquest": {
    "service": "Mapquest",
    "category": "Web Mapping Service",
    "impact": "Unauthorized access to and manipulation of mapping data and services, potentially leading to excessive API usage charges or data scraping of geographic information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Mapquest API key.\n2. Use the key to perform geocoding, route calculation, or map display via the Mapquest API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Mapquest API key immediately."
  },
  "Marketstack": {
    "service": "Marketstack",
    "category": "Real-time Market Data",
    "impact": "Unauthorized access to real-time market data, potentially leading to excessive API usage charges or data scraping of sensitive financial information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Marketstack API key.\n2. Use the key to fetch real-time stock data or historical data via the Marketstack API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Marketstack API key immediately."
  },
  "MattermostPersonalToken": {
    "service": "Mattermost",
    "category": "Online Chat Service",
    "impact": "Unauthorized authentication and API requests to a Mattermost server, potentially leading to access to private channels, sending messages as another user, or exfiltration of sensitive communication data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Mattermost Personal Token.\n2. Configure Mattermost CLI or use a direct API call with the found token.\n3. Attempt to list channels, read messages from a private channel, or post a message.",
    "remediation": "Revoke the exposed Mattermost Personal Token immediately through Mattermost's user settings. Review audit logs for unauthorized access or activity."
  },
  "Mavenlink": {
    "service": "Mavenlink",
    "category": "Project Management Software",
    "impact": "Unauthorized access to and modification of project data, potentially leading to project disruption, data theft, or exposure of sensitive project details and financial information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Mavenlink API key.\n2. Attempt to list projects, tasks, or financial data using the Mavenlink API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Mavenlink API key immediately."
  },
  "MaxMindLicense": {
    "service": "MaxMind",
    "category": "IP Intelligence",
    "impact": "Unauthorized access to GeoIP databases and services, potentially leading to excessive usage or misuse of geolocation data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed MaxMind license key.\n2. Use the key to download GeoIP databases or query the GeoIP services.\n3. Verify successful access.",
    "remediation": "Rotate the MaxMind license key immediately."
  },
  "MeaningCloud": {
    "service": "MeaningCloud",
    "category": "Text Analytics Service",
    "impact": "Unauthorized access to and utilization of text analytics services, potentially leading to excessive API usage charges or the processing of sensitive unstructured content without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed MeaningCloud API key.\n2. Attempt to perform sentiment analysis or text classification on sample text using the MeaningCloud API with the found key.\n3. Verify successful analysis.",
    "remediation": "Rotate the MeaningCloud API key immediately."
  },
  "MediaStack": {
    "service": "MediaStack",
    "category": "Real-time News Data",
    "impact": "Unauthorized access to real-time news data, potentially leading to excessive API usage charges or data scraping of news articles.",
    "severity": "Low",
    "poc_template": "1. Locate exposed MediaStack API key.\n2. Use the key to fetch news articles via the MediaStack API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the MediaStack API key immediately."
  },
  "Meistertask": {
    "service": "Meistertask",
    "category": "Task Management Tool",
    "impact": "Unauthorized access to and modification of project and task data, potentially leading to project disruption, data theft, or exposure of sensitive task details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Meistertask API key.\n2. Attempt to list projects or modify tasks using the Meistertask API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Meistertask API key immediately."
  },
  "Meraki": {
    "service": "Cisco Meraki",
    "category": "Cloud-managed IT Solutions",
    "impact": "Unauthorized access to and management of networking, security, and device management configurations, potentially leading to network disruption, security bypasses, or exposure of sensitive network data. Full control over IT infrastructure.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Meraki API keys.\n2. Attempt to list networks, modify firewall rules, or access device configurations via the Meraki API.\n3. Verify successful administrative access and resource manipulation.",
    "remediation": "Immediately revoke the exposed Meraki API keys and generate new ones. Implement strong access controls and multi-factor authentication for Meraki accounts. Review all audit logs for unauthorized changes."
  },
  "Mesibo": {
    "service": "Mesibo",
    "category": "Real-time Communication Platform",
    "impact": "Unauthorized access to and interaction with the Mesibo API, allowing for messaging, voice, and video calls to be added to applications, potentially leading to unauthorized communication, eavesdropping, or resource abuse.",
    "severity": "High",
    "poc_template": "1. Locate exposed Mesibo tokens.\n2. Attempt to send a message or initiate a call using the Mesibo API with the found tokens.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Mesibo tokens immediately."
  },
  "MessageBird": {
    "service": "MessageBird",
    "category": "Cloud Communications Platform",
    "impact": "Unauthorized sending and receiving of SMS, voice, and chat messages, potentially leading to spamming, phishing attacks, or unauthorized access to communication data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed MessageBird API keys.\n2. Attempt to send a test SMS message or initiate a voice call using the MessageBird API with the found keys.\n3. Verify successful message delivery/call initiation.",
    "remediation": "Revoke and regenerate the MessageBird API keys immediately. Review MessageBird logs for unauthorized activity."
  },
  "MetaAPI": {
    "service": "MetaAPI",
    "category": "API Service",
    "impact": "Unauthorized access to the MetaAPI service, potentially leading to resource abuse, data breaches, or disruption of services, depending on the service's functionality.",
    "severity": "High",
    "poc_template": "1. Locate exposed MetaAPI credentials (API keys).\n2. Attempt to access or modify data/resources using the MetaAPI with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed MetaAPI credentials and generate new ones immediately."
  },
  "Metabase": {
    "service": "Metabase",
    "category": "Business Intelligence Tool",
    "impact": "Unauthorized access to and interaction with the Metabase API, potentially leading to access to sensitive business data, manipulation of dashboards, or exposure of confidential insights.",
    "severity": "High",
    "poc_template": "1. Locate exposed Metabase session token.\n2. Attempt to access dashboards or query databases using the Metabase API with the found token.\n3. Verify successful data access.",
    "remediation": "Invalidate the Metabase session token immediately. If it's a long-lived token, consider it compromised and rotate relevant credentials."
  },
  "Metrilo": {
    "service": "Metrilo",
    "category": "E-commerce Analytics & CRM",
    "impact": "Unauthorized access to and management of e-commerce data, potentially leading to exposure of sensitive sales metrics, customer information, or manipulation of marketing data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Metrilo API key.\n2. Attempt to retrieve sales data or customer profiles using the Metrilo API with the found key.\n3. Verify successful data access.",
    "remediation": "Rotate the Metrilo API key immediately."
  },
  "MicrosoftTeamsWebhook": {
    "service": "Microsoft Teams",
    "category": "Collaboration & Communication",
    "impact": "Unauthorized sending of messages to Microsoft Teams channels, potentially leading to spamming, phishing attempts, or disruption of team communication.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Microsoft Teams Webhook URL.\n2. Construct a simple JSON payload and send a POST request to the webhook URL.\n3. Verify that the message appears in the specified Teams channel.",
    "remediation": "Delete or regenerate the Microsoft Teams Webhook URL immediately. Review the channel for any unauthorized messages."
  },
  "Mindmeister": {
    "service": "Mindmeister",
    "category": "Mind Mapping Tool",
    "impact": "Unauthorized access to and manipulation of mind maps and other data within the platform, potentially leading to intellectual property theft, content tampering, or disruption of collaborative thought processes.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Mindmeister API key.\n2. Attempt to list mind maps or modify a mind map using the Mindmeister API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Mindmeister API key immediately."
  },
  "Miro": {
    "service": "Miro",
    "category": "Online Collaborative Whiteboarding",
    "impact": "Unauthorized access to and modification of data and collaboration on whiteboards, potentially leading to intellectual property theft, content tampering, or disruption of collaborative work.",
    "severity": "High",
    "poc_template": "1. Locate exposed Miro API key.\n2. Attempt to list boards or modify content on a board using the Miro API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Miro API key immediately."
  },
  "Mite": {
    "service": "Mite",
    "category": "Time Tracking Tool",
    "impact": "Unauthorized access to and modification of time tracking data, potentially leading to inaccurate billing, financial fraud, or exposure of sensitive project and client time details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Mite API key.\n2. Attempt to retrieve or modify time entries using the Mite API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Mite API key immediately."
  },
  "Mixmax": {
    "service": "Mixmax",
    "category": "Email Enhancement & Automation",
    "impact": "Unauthorized access to and management of email communication and automation features, potentially leading to unauthorized email sending, spamming, or access to sensitive email content and recipient data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Mixmax API token.\n2. Attempt to send an email or access email insights using the Mixmax API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Mixmax API token immediately and generate a new one."
  },
  "Mockaroo": {
    "service": "Mockaroo",
    "category": "Realistic Data Generation",
    "impact": "Unauthorized access to and generation of realistic data, potentially leading to excessive API usage charges or the generation of data that could be misused in testing environments.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Mockaroo API key.\n2. Use the key to generate test data based on a schema via the Mockaroo API.\n3. Verify successful data generation.",
    "remediation": "Rotate the Mockaroo API key immediately."
  },
  "Moderation": {
    "service": "Moderation API",
    "category": "Content Moderation",
    "impact": "Unauthorized access to content moderation services, potentially leading to bypassing content filters, injecting malicious content for analysis, or excessive API usage charges.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Moderation API key.\n2. Use the key to submit text or media for moderation via the Moderation API.\n3. Verify successful moderation analysis.",
    "remediation": "Rotate the Moderation API key immediately."
  },
  "Monday": {
    "service": "Monday.com",
    "category": "Work Operating System",
    "impact": "Unauthorized access to and modification of data and workflows on the platform, potentially leading to project disruption, data theft, or exposure of sensitive project and task information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Monday API key.\n2. Attempt to list boards, create items, or modify columns using the Monday API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Monday API key immediately."
  },
  "MongoDB": {
    "service": "MongoDB",
    "category": "NoSQL Database",
    "impact": "Unauthorized access to and manipulation of the database, potentially leading to complete data compromise, data exfiltration, injection of malicious data, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed MongoDB credentials (connection string containing username/password/host).\n2. Attempt to connect to the MongoDB instance using a MongoDB client (e.g., mongosh, MongoDB Compass) with the found credentials.\n3. Verify successful connection and attempt to query/modify sensitive collections.",
    "remediation": "Immediately rotate MongoDB credentials and ensure connection strings are not exposed. Implement strong access controls, network segmentation, and encryption for database connections."
  },
  "MonkeyLearn": {
    "service": "MonkeyLearn",
    "category": "Machine Learning Platform",
    "impact": "Unauthorized access to and management of custom machine learning models and text analysis services, potentially leading to resource abuse, exposure of proprietary models, or manipulation of analytical results.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed MonkeyLearn API key.\n2. Attempt to classify text or extract entities using a custom model via the MonkeyLearn API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the MonkeyLearn API key immediately."
  },
  "Moonclerk": {
    "service": "Moonclerk",
    "category": "Online Payment System",
    "impact": "Unauthorized management and access to payment data, potentially leading to financial fraud, unauthorized recurring payment collection, or exposure of sensitive payment information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Moonclerk API key.\n2. Attempt to retrieve payment forms, customer data, or initiate a payment using the Moonclerk API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Moonclerk API key immediately. Review all transaction logs for unauthorized activity."
  },
  "Moosend": {
    "service": "Moosend",
    "category": "Email Marketing Service Provider",
    "impact": "Unauthorized access to and management of email marketing campaigns, subscriber lists, and other related data, potentially leading to unauthorized email sending, spamming, data breaches of subscriber lists, or manipulation of marketing efforts.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Moosend API key.\n2. Attempt to list subscriber lists, send a test campaign, or modify subscriber data using the Moosend API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Moosend API key immediately. Review Moosend audit logs for any unauthorized activities."
  },
  "Moralis": {
    "service": "Moralis",
    "category": "dApp Development Platform",
    "impact": "Unauthorized interaction with blockchain data and services, potentially leading to resource abuse, monitoring of on-chain activity, or unauthorized execution of blockchain functions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Moralis API key.\n2. Attempt to fetch blockchain data (e.g., token balances, NFT metadata) or interact with a smart contract using the Moralis API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Moralis API key immediately."
  },
  "Mrticktock": {
    "service": "Mrticktock",
    "category": "Time Tracking Service",
    "impact": "Unauthorized access to and management of time-based activities and associated data, potentially leading to inaccurate billing, financial fraud, or exposure of sensitive project time details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Mrticktock credentials.\n2. Attempt to retrieve or modify timers and associated data using the Mrticktock API with the found credentials.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Mrticktock credentials immediately."
  },
  "Mux": {
    "service": "Mux",
    "category": "Video Streaming Service",
    "impact": "Unauthorized access to and management of video assets and streaming data, potentially leading to unauthorized video deletion, content manipulation, or disruption of video streaming services.",
    "severity": "High",
    "poc_template": "1. Locate exposed Mux API keys.\n2. Attempt to list video assets, create new assets, or retrieve analytics data using the Mux API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Mux API keys immediately."
  },
  "MyIntervals": {
    "service": "MyIntervals",
    "category": "Project Management Tool",
    "impact": "Unauthorized access to and modification of project data and user information, potentially leading to project disruption, data theft, or exposure of sensitive project details and personal data.",
    "severity": "High",
    "poc_template": "1. Locate exposed MyIntervals API key.\n2. Attempt to list projects, tasks, or user details using the MyIntervals API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the MyIntervals API key immediately."
  },
  "Myfreshworks": {
    "service": "Freshworks",
    "category": "Customer Engagement Platform",
    "impact": "Unauthorized access to and management of various customer engagement services (CRM, IT service management), potentially leading to data breaches, manipulation of customer records, or disruption of support operations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Freshworks API key.\n2. Attempt to list tickets, manage contacts, or access other Freshworks service data using the Freshworks API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Freshworks API key immediately."
  },
  "NGCNvidia": {
    "service": "NVIDIA NGC API",
    "category": "AI/ML Platform",
    "impact": "Unauthorized access to and management of user data and performance of actions on behalf of users within NVIDIA's NGC platform, potentially leading to resource abuse, access to proprietary AI models, or sensitive data manipulation.",
    "severity": "High",
    "poc_template": "1. Locate exposed NVIDIA NGC API key.\n2. Attempt to list resources (e.g., models, containers) or perform actions (e.g., download a model) using the NGC API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed NVIDIA NGC API key and generate a new one immediately."
  },
  "NVAPI": {
    "service": "NVIDIA NGC API",
    "category": "AI/ML Platform",
    "impact": "Unauthorized access to and management of user data and performance of actions on behalf of users within NVIDIA's NGC platform, potentially leading to resource abuse, access to proprietary AI models, or sensitive data manipulation.",
    "severity": "High",
    "poc_template": "1. Locate exposed NVAPI keys (likely NGC API keys).\n2. Attempt to list resources (e.g., models, containers) or perform actions (e.g., download a model) using the NGC API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed NVAPI keys and generate new ones immediately."
  },
  "Nethunt": {
    "service": "Nethunt",
    "category": "CRM Tool",
    "impact": "Unauthorized access to and management of CRM data, potentially leading to data breaches, lead manipulation, or exposure of sensitive customer information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Nethunt credentials.\n2. Attempt to list or modify CRM data (e.g., contacts, deals) using the Nethunt API with the found credentials.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Nethunt credentials immediately."
  },
  "Netlify": {
    "service": "Netlify",
    "category": "Cloud Platform for Web Developers",
    "impact": "Unauthorized management of sites, deployment of applications, and access to various services offered by the platform, potentially leading to website defacement, unauthorized code injection, or data exfiltration from hosted applications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Netlify API key.\n2. Configure Netlify CLI with the found key.\n3. Attempt to list sites, deploy a new site, or access build logs.\n4. Verify successful access and resource manipulation.",
    "remediation": "Immediately revoke the exposed Netlify API key and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Netsuite": {
    "service": "Netsuite",
    "category": "Cloud Business Management Suite",
    "impact": "Unauthorized access to and modification of data within Netsuite, potentially leading to financial fraud, supply chain disruption, data breaches across ERP, CRM, and e-commerce modules.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Netsuite credentials.\n2. Attempt to access or modify sensitive data within Netsuite (e.g., financial records, customer data, inventory) via its API or UI (if credentials are for a user).\n3. Verify successful data manipulation.",
    "remediation": "Immediately rotate Netsuite credentials. Implement strong access controls, multi-factor authentication, and review all audit logs for unauthorized activities."
  },
  "NeutrinoApi": {
    "service": "Neutrino API",
    "category": "Data & Security Tools",
    "impact": "Unauthorized access to a variety of services including data tools and security tools, potentially leading to excessive API usage charges or misuse of data validation/security features.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Neutrino API key.\n2. Use the key to call a service (e.g., validate an email, perform a IP lookup) via the Neutrino API.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Neutrino API key immediately."
  },
  "NewRelicPersonalApiKey": {
    "service": "New Relic",
    "category": "Software Analytics & Performance Monitoring",
    "impact": "Unauthorized access to and management of New Relic account and data, potentially leading to exposure of sensitive performance metrics, application logs, or manipulation of monitoring configurations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed New Relic Personal API key.\n2. Attempt to query application data, list alerts, or modify monitoring settings using the New Relic API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed New Relic Personal API key immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Newsapi": {
    "service": "NewsAPI",
    "category": "News Data",
    "impact": "Unauthorized access to news articles from various sources, potentially leading to excessive API usage charges or data scraping of news content.",
    "severity": "Low",
    "poc_template": "1. Locate exposed NewsAPI key.\n2. Use the key to query news articles via the NewsAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the NewsAPI key immediately."
  },
  "Newscatcher": {
    "service": "Newscatcher",
    "category": "News Article Search",
    "impact": "Unauthorized access to search and retrieve news articles from various sources, potentially leading to excessive API usage charges or data scraping of news content.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Newscatcher API key.\n2. Use the key to search for news articles via the Newscatcher API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Newscatcher API key immediately."
  },
  "NexmoApiKey": {
    "service": "Nexmo (Vonage API)",
    "category": "Communications API",
    "impact": "Unauthorized access to and management of SMS, voice, and phone verification services, potentially leading to unauthorized message sending, phone call manipulation, or resource abuse.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Nexmo API keys.\n2. Attempt to send a test SMS message or initiate a phone call using the Nexmo API with the found keys.\n3. Verify successful message delivery/call initiation.",
    "remediation": "Revoke and regenerate the Nexmo API keys immediately. Review Nexmo logs for unauthorized activity."
  },
  "Nftport": {
    "service": "Nftport",
    "category": "NFT Interaction Service",
    "impact": "Unauthorized access to and management of NFT data and transactions, potentially leading to unauthorized NFT minting, transfers, or access to sensitive NFT ownership information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Nftport API key.\n2. Attempt to mint an NFT, retrieve NFT metadata, or initiate a transaction using the Nftport API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Nftport API key immediately."
  },
  "Ngrok": {
    "service": "Ngrok",
    "category": "Tunneling Service",
    "impact": "Unauthorized management and control of secure introspectable tunnels to localhost, potentially leading to exposure of internal services, bypassing network security, or resource abuse.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Ngrok keys.\n2. Configure Ngrok CLI with the found keys.\n3. Attempt to list active tunnels, create new tunnels, or inspect tunnel traffic.\n4. Verify successful access and control over tunneling.",
    "remediation": "Revoke and regenerate the Ngrok keys immediately. Review Ngrok logs for unauthorized tunnel creation or access."
  },
  "Nicereply": {
    "service": "Nicereply",
    "category": "Customer Satisfaction Survey Tool",
    "impact": "Unauthorized access to and management of survey data and user statistics, potentially leading to data manipulation, exposure of sensitive customer feedback, or disruption of survey collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Nicereply API key.\n2. Attempt to retrieve survey results or user statistics using the Nicereply API with the found key.\n3. Verify successful data access.",
    "remediation": "Rotate the Nicereply API key immediately."
  },
  "Nightfall": {
    "service": "Nightfall",
    "category": "Data Security Platform",
    "impact": "Unauthorized interaction with Nightfall's API, potentially leading to bypassing sensitive data detection and protection, configuring unauthorized data policies, or exfiltration of scanned data results.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Nightfall API key.\n2. Attempt to scan data for sensitive information or configure detection policies using the Nightfall API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Nightfall API key and generate a new one immediately. Review Nightfall audit logs for any unauthorized activities."
  },
  "Nimble": {
    "service": "Nimble",
    "category": "Customer Relationship Management (CRM)",
    "impact": "Unauthorized access to and modification of customer records and other CRM functionalities, potentially leading to data breaches, lead manipulation, or exposure of sensitive customer interactions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Nimble API key.\n2. Attempt to list or modify customer contacts or deals using the Nimble API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Nimble API key immediately."
  },
  "Noticeable": {
    "service": "Noticeable",
    "category": "Changelog & Release Notes Service",
    "impact": "Unauthorized access to and modification of changelogs and release notes, potentially leading to unauthorized content publishing, content tampering, or disruption of communication to users.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Noticeable API key.\n2. Attempt to list changelogs or create a new release note using the Noticeable API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Noticeable API key immediately."
  },
  "Notion": {
    "service": "Notion",
    "category": "Productivity Tool & Workspace",
    "impact": "Unauthorized access to and modification of data within a user's Notion workspace, including notes, databases, projects, and collaborative content, potentially leading to data theft, content tampering, or disruption of productivity.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Notion API key.\n2. Attempt to list pages, read content from a database, or create new blocks using the Notion API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the exposed Notion API key immediately through Notion's integration settings. Review Notion audit logs for unauthorized activities."
  },
  "NozbeTeams": {
    "service": "NozbeTeams",
    "category": "Collaborative Task & Project Management",
    "impact": "Unauthorized access to and management of tasks and projects within a NozbeTeams account, potentially leading to project disruption, data theft, or exposure of sensitive project details.",
    "severity": "High",
    "poc_template": "1. Locate exposed NozbeTeams API key.\n2. Attempt to list projects or modify tasks using the NozbeTeams API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the NozbeTeams API key immediately."
  },
  "NpmToken": {
    "service": "NPM",
    "category": "Package Manager (JavaScript)",
    "impact": "Unauthorized authentication and publishing of packages to the NPM registry, potentially leading to supply chain attacks (injecting malicious code into widely used packages), package deletion, or unauthorized access to private packages.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed NPM token.\n2. Configure NPM CLI with the found token.\n3. Attempt to publish a new package, update an existing package, or list private packages accessible with the token.\n4. Verify successful package manipulation.",
    "remediation": "Immediately revoke the exposed NPM token through your NPM account settings. Enable two-factor authentication for your NPM account and audit any packages published or modified."
  },
  "NuGetApiKey": {
    "service": "NuGet",
    "category": ".NET Package Manager",
    "impact": "Unauthorized publishing and management of packages in the NuGet repository, potentially leading to supply chain attacks (injecting malicious code into widely used packages), package deletion, or unauthorized access to private packages.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed NuGet API key.\n2. Configure NuGet CLI with the found key.\n3. Attempt to push a new package, list package versions, or delete a package.\n4. Verify successful package manipulation.",
    "remediation": "Immediately revoke the exposed NuGet API key through your NuGet account settings. Ensure API keys have minimal necessary permissions and audit any packages published or modified."
  },
  "Numverify": {
    "service": "Numverify",
    "category": "Phone Number Validation",
    "impact": "Unauthorized validation of phone numbers and gathering of information about them, potentially leading to excessive API usage charges or misuse of the service for reconnaissance or spamming purposes.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Numverify API key.\n2. Use the key to validate a phone number via the Numverify API.\n3. Verify successful validation result.",
    "remediation": "Rotate the Numverify API key immediately."
  },
  "Nutritionix": {
    "service": "Nutritionix",
    "category": "Food Tracking API",
    "impact": "Unauthorized access to and logging of nutritional data, potentially leading to excessive API usage charges or the logging of inaccurate dietary information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Nutritionix API keys.\n2. Use the keys to search for food items or log nutritional entries via the Nutritionix API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Nutritionix API keys immediately."
  },
  "Nylas": {
    "service": "Nylas",
    "category": "Email, Calendar, & Contacts APIs",
    "impact": "Unauthorized access to and management of email, calendar, and contacts, potentially leading to unauthorized email sending, calendar manipulation, contact data exfiltration, or account impersonation.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Nylas API keys.\n2. Attempt to list emails, create calendar events, or access contact lists using the Nylas API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Nylas API keys immediately. Review all connected accounts for unauthorized activities."
  },
  "OOPSpam": {
    "service": "OOPSpam",
    "category": "Spam Detection Service",
    "impact": "Unauthorized verification and detection of spam content, potentially leading to bypassing spam filters, injecting false spam classifications, or excessive API usage charges.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed OOPSpam API key.\n2. Use the key to submit content for spam detection via the OOPSpam API.\n3. Verify successful spam detection result.",
    "remediation": "Rotate the OOPSpam API key immediately."
  },
  "Oanda": {
    "service": "Oanda",
    "category": "Forex Trading Platform",
    "impact": "Unauthorized access to and management of trading accounts, execution of trades, and retrieval of market data, potentially leading to financial fraud, unauthorized forex trades, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Oanda API keys.\n2. Attempt to retrieve account balance, execute a trade, or fetch market data using the Oanda API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Oanda API keys immediately. Implement IP whitelisting and review all trading logs for unauthorized activity."
  },
  "Okta": {
    "service": "Okta",
    "category": "Identity & Access Management",
    "impact": "Unauthorized authentication and access to various resources and APIs within an organization, potentially leading to privilege escalation, account takeover, or access to sensitive applications and data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Okta tokens.\n2. Attempt to use the token to access Okta APIs (e.g., list users, modify policies) or federated applications.\n3. Verify successful authentication and authorization.",
    "remediation": "Immediately revoke the exposed Okta tokens through the Okta administrative console. Review Okta audit logs for any unauthorized access or configuration changes."
  },
  "Omnisend": {
    "service": "Omnisend",
    "category": "Marketing Automation Platform (E-commerce)",
    "impact": "Unauthorized access to and management of marketing campaigns, contacts, and other resources, potentially leading to unauthorized email/SMS sending, data breaches of subscriber lists, or manipulation of e-commerce marketing efforts.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Omnisend API key.\n2. Attempt to list contacts, send a test campaign, or modify marketing automation workflows using the Omnisend API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Omnisend API key immediately. Review Omnisend audit logs for any unauthorized activities."
  },
  "OneLogin": {
    "service": "OneLogin",
    "category": "Identity & Access Management",
    "impact": "Unauthorized authentication and authorization to API requests, potentially leading to privilege escalation, account takeover, or access to sensitive applications and data managed by OneLogin.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed OneLogin OAuth client IDs and secrets.\n2. Attempt to use these credentials to obtain an OAuth token and interact with OneLogin APIs (e.g., list users, manage applications).\n3. Verify successful authentication and authorization.",
    "remediation": "Immediately revoke the exposed OneLogin OAuth client secrets and regenerate them. Review OneLogin audit logs for any unauthorized access or configuration changes."
  },
  "Onedesk": {
    "service": "Onedesk",
    "category": "Customer Service & Project Management",
    "impact": "Unauthorized access to and management of customer service tickets and project tasks, potentially leading to data breaches, support ticket manipulation, or disruption of project workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Onedesk credentials.\n2. Attempt to list tickets or modify project tasks using the Onedesk API with the found credentials.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Onedesk credentials immediately."
  },
  "OnepageCRM": {
    "service": "OnepageCRM",
    "category": "Simple CRM System",
    "impact": "Unauthorized access to and management of contacts, deals, and other CRM data, potentially leading to data breaches, lead manipulation, or exposure of sensitive customer information.",
    "severity": "High",
    "poc_template": "1. Locate exposed OnepageCRM API keys.\n2. Attempt to list or modify contacts or deals using the OnepageCRM API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the OnepageCRM API keys immediately."
  },
  "Onesignal": {
    "service": "OneSignal",
    "category": "Customer Engagement Platform",
    "impact": "Unauthorized sending of push notifications, in-app messages, SMS, and emails, potentially leading to spamming, phishing attacks, or unauthorized communication with customers.",
    "severity": "High",
    "poc_template": "1. Locate exposed OneSignal API keys.\n2. Attempt to send a test push notification or retrieve user data using the OneSignal API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the OneSignal API keys immediately. Review OneSignal logs for unauthorized message sending."
  },
  "Onfleet": {
    "service": "Onfleet",
    "category": "Delivery Management Software",
    "impact": "Unauthorized access to and management of delivery data and operations, potentially leading to unauthorized delivery modification, access to driver/customer information, or disruption of logistics.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Onfleet API keys.\n2. Attempt to retrieve task details, modify delivery status, or access driver locations using the Onfleet API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Onfleet API keys immediately. Review all delivery logs for unauthorized activity."
  },
  "OpenAI": {
    "service": "OpenAI",
    "category": "AI Models & Services",
    "impact": "Unauthorized access to and interaction with various AI models and services, potentially leading to excessive API usage charges, generation of harmful content, or exposure of proprietary AI interactions.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed OpenAI API key.\n2. Attempt to generate text, complete a prompt, or use another OpenAI model via the API with the found key.\n3. Verify successful API interaction and response.",
    "remediation": "Revoke the exposed OpenAI API key immediately through the OpenAI platform. Review usage logs for any unauthorized activities."
  },
  "OpenCageData": {
    "service": "OpenCageData",
    "category": "Geocoding API",
    "impact": "Unauthorized access to geocoding capabilities, potentially leading to excessive API usage charges or data scraping of location data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed OpenCageData key.\n2. Use the key to convert an address to coordinates or vice versa via the OpenCageData API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the OpenCageData key immediately."
  },
  "OpenVpn": {
    "service": "OpenVPN",
    "category": "Virtual Private Network (VPN)",
    "impact": "Unauthorized management and configuration of VPN connections and settings, potentially leading to unauthorized network access, bypassing security controls, or disruption of secure communications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed OpenVPN API credentials.\n2. Attempt to configure or connect to a VPN server using the OpenVPN API with the found credentials.\n3. Verify successful connection or configuration changes.",
    "remediation": "Immediately rotate OpenVPN API credentials. Review VPN server logs for any unauthorized connections."
  },
  "OpenWeather": {
    "service": "OpenWeather",
    "category": "Weather Data & Forecasting",
    "impact": "Unauthorized access to weather data and forecasting services, potentially leading to excessive API usage charges or data scraping of weather information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed OpenWeather API key.\n2. Use the key to fetch current weather data or a forecast via the OpenWeather API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the OpenWeather API key immediately."
  },
  "Openuv": {
    "service": "Openuv",
    "category": "UV Index Data API",
    "impact": "Unauthorized access to UV index data, potentially leading to excessive API usage charges or data scraping of environmental information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Openuv API key.\n2. Use the key to retrieve UV index information for a location via the Openuv API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Openuv API key immediately."
  },
  "Opsgenie": {
    "service": "Opsgenie",
    "category": "Alerting & Incident Management",
    "impact": "Unauthorized interaction with the Opsgenie API to manage alerts and incidents, potentially leading to disruption of incident response, silencing of critical alerts, or exposure of sensitive incident details.",
    "severity": "High",
    "poc_template": "1. Locate exposed Opsgenie API key.\n2. Attempt to list alerts, acknowledge an alert, or create a new incident using the Opsgenie API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Opsgenie API key immediately."
  },
  "Optimizely": {
    "service": "Optimizely",
    "category": "A/B Testing & Feature Flagging",
    "impact": "Unauthorized management and access to A/B testing and feature flagging services, potentially leading to unauthorized experiment rollouts, manipulation of feature visibility, or exposure of sensitive experimentation data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Optimizely API key.\n2. Attempt to list experiments or modify feature flags using the Optimizely API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Optimizely API key immediately."
  },
  "Overloop": {
    "service": "Overloop",
    "category": "API Platform",
    "impact": "Unauthorized interaction with the Overloop API to manage and retrieve user data, potentially leading to data breaches, account manipulation, or exposure of sensitive user information, depending on the service's functionality.",
    "severity": "High",
    "poc_template": "1. Locate exposed Overloop API key.\n2. Attempt to access or modify user data/resources using the Overloop API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Overloop API key and generate a new one immediately."
  },
  "Owlbot": {
    "service": "Owlbot",
    "category": "Dictionary API",
    "impact": "Unauthorized access to dictionary definitions, synonyms, and example sentences, potentially leading to excessive API usage charges or data scraping of linguistic information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Owlbot API key.\n2. Use the key to retrieve definitions for a word via the Owlbot API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Owlbot API key immediately."
  },
  "PackageCloud": {
    "service": "PackageCloud",
    "category": "Software Package Hosting & Distribution",
    "impact": "Unauthorized management and access to software packages, potentially leading to unauthorized package uploads, package deletion, or supply chain attacks by injecting malicious code into distributed packages.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed PackageCloud API key.\n2. Attempt to list repositories, upload a package, or delete a package using the PackageCloud API with the found key.\n3. Verify successful package manipulation.",
    "remediation": "Revoke and regenerate the PackageCloud API key immediately. Review PackageCloud logs for unauthorized activities."
  },
  "Pagarme": {
    "service": "Pagarme",
    "category": "Payment Service Provider",
    "impact": "Unauthorized access to and management of payment transactions and other related services, potentially leading to financial fraud, unauthorized payment processing, or exposure of sensitive payment information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Pagarme API keys.\n2. Attempt to retrieve transaction details or initiate a payment using the Pagarme API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Pagarme API keys immediately. Review all transaction logs for unauthorized activity."
  },
  "PagerDutyApiKey": {
    "service": "PagerDuty",
    "category": "Incident Management Platform",
    "impact": "Unauthorized access to and management of incident management functionalities, including reliable notifications, automatic escalations, and on-call scheduling, potentially leading to disruption of incident response, silencing of critical alerts, or exposure of sensitive incident details.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed PagerDuty API key.\n2. Attempt to list incidents, trigger an incident, or acknowledge an alert using the PagerDuty API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed PagerDuty API key immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "PandaScore": {
    "service": "PandaScore",
    "category": "Esports Data Provider",
    "impact": "Unauthorized access to a wide range of esports statistics and live data, potentially leading to excessive API usage charges or data scraping of proprietary esports information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed PandaScore API key.\n2. Use the key to fetch esports match data or player statistics via the PandaScore API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the PandaScore API key immediately."
  },
  "Pandadoc": {
    "service": "Pandadoc",
    "category": "Document Automation Software",
    "impact": "Unauthorized access to and management of digital documents, potentially leading to unauthorized document signing, content tampering, or exposure of sensitive contract and proposal information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Pandadoc API keys.\n2. Attempt to list documents, send a document for signature, or modify document templates using the Pandadoc API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Pandadoc API keys immediately."
  },
  "Paperform": {
    "service": "Paperform",
    "category": "Form Builder",
    "impact": "Unauthorized access to proprietary or not public form data, potentially leading to data breaches, exposure of sensitive collected information, or manipulation of form submissions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Paperform API keys.\n2. Attempt to read proprietary form data or form submissions using the Paperform API with the found keys.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Paperform API keys immediately."
  },
  "ParallelDots": {
    "service": "ParallelDots",
    "category": "AI Service (Text Analysis)",
    "impact": "Unauthorized access to various APIs for text analysis, potentially leading to excessive API usage charges or the processing of sensitive text without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ParallelDots API key.\n2. Use the key to perform sentiment analysis or keyword extraction on sample text via a ParallelDots API.\n3. Verify successful analysis.",
    "remediation": "Rotate the ParallelDots API key immediately."
  },
  "Parsehub": {
    "service": "Parsehub",
    "category": "Web Scraping Service",
    "impact": "Unauthorized access to and management of web scraping projects, potentially leading to excessive API usage charges, unauthorized data extraction from websites, or exposure of sensitive scraping configurations.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Parsehub API key.\n2. Attempt to list projects or run a scraping job using the Parsehub API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Parsehub API key immediately."
  },
  "Parsers": {
    "service": "Parsers",
    "category": "SQL Query Parsing Service",
    "impact": "Unauthorized access to and modification of SQL queries, potentially leading to injection of malicious queries, manipulation of data definitions, or exposure of sensitive query structures.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Parsers API key.\n2. Attempt to parse or modify a SQL query using the Parsers API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Parsers API key immediately."
  },
  "Parseur": {
    "service": "Parseur",
    "category": "Document Parsing Software",
    "impact": "Unauthorized access to and management of data extracted from emails and other documents, potentially leading to data breaches, manipulation of extracted information, or exposure of sensitive document content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Parseur API key.\n2. Attempt to list mailboxes or retrieve parsed data from documents using the Parseur API with the found key.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Parseur API key immediately."
  },
  "Partnerstack": {
    "service": "PartnerStack",
    "category": "Partner Management Platform",
    "impact": "Unauthorized access to and management of partner programs, potentially leading to unauthorized partner creation, manipulation of commission structures, or exposure of sensitive partner data.",
    "severity": "High",
    "poc_template": "1. Locate exposed PartnerStack API key.\n2. Attempt to list partners or modify program settings using the PartnerStack API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the PartnerStack API key immediately."
  },
  "Pastebin": {
    "service": "Pastebin",
    "category": "Text Storage Service",
    "impact": "Unauthorized access to and manipulation of stored data, potentially leading to exposure of sensitive information, injection of malicious content, or content deletion.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Pastebin keys.\n2. Attempt to list pastes, create a new paste, or delete an existing paste using the Pastebin API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Pastebin keys immediately."
  },
  "Paydirtapp": {
    "service": "Paydirtapp",
    "category": "Time Tracking & Invoicing App",
    "impact": "Unauthorized access to and management of user data and billing information, potentially leading to financial fraud, inaccurate invoicing, or exposure of sensitive financial details.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Paydirtapp API key.\n2. Attempt to retrieve time entries, generate invoices, or access client data using the Paydirtapp API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Paydirtapp API key immediately."
  },
  "Paymoapp": {
    "service": "Paymoapp",
    "category": "Project Management & Collaboration",
    "impact": "Unauthorized access to and modification of project data and user information, potentially leading to project disruption, data theft, or exposure of sensitive project details and personal data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Paymoapp API key.\n2. Attempt to list projects, tasks, or user details using the Paymoapp API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Paymoapp API key immediately."
  },
  "Paymongo": {
    "service": "PayMongo",
    "category": "Payment Processing Platform (Philippines)",
    "impact": "Unauthorized access to and management of payment methods, transactions, and other related data, potentially leading to financial fraud, unauthorized payment processing, or exposure of sensitive payment information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed PayMongo API keys.\n2. Attempt to retrieve transaction details, create a payment intent, or list payment methods using the PayMongo API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the PayMongo API keys immediately. Review all transaction logs for unauthorized activity."
  },
  "PaypalOauth": {
    "service": "PayPal",
    "category": "Payment Gateway",
    "impact": "Unauthorized authentication with PayPal's API and performance of transactions on behalf of a PayPal account, potentially leading to financial fraud, unauthorized fund transfers, or access to sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed PayPal OAuth credentials (access token or refresh token).\n2. Use the token to make an API request to PayPal (e.g., get account details, initiate a payment).\n3. Verify successful transaction or data access.",
    "remediation": "Immediately revoke the exposed PayPal OAuth token through your PayPal account security settings. Review all transaction logs for unauthorized activity."
  },
  "Paystack": {
    "service": "Paystack",
    "category": "Payment Processing Service",
    "impact": "Unauthorized access to and management of payment transactions and customer data, potentially leading to financial fraud, unauthorized payment processing, or exposure of sensitive customer billing information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Paystack API keys.\n2. Attempt to retrieve transaction details or initiate a payment using the Paystack API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Paystack API keys immediately. Review all transaction logs for unauthorized activity."
  },
  "PdfLayer": {
    "service": "PdfLayer",
    "category": "HTML to PDF Conversion",
    "impact": "Unauthorized access to and utilization of the PDF conversion service, potentially leading to excessive API usage charges or the generation of unauthorized PDF documents from sensitive HTML.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed PdfLayer API key.\n2. Attempt to convert HTML content to a PDF document using the PdfLayer API with the found key.\n3. Verify successful PDF generation.",
    "remediation": "Rotate the PdfLayer API key immediately."
  },
  "PdfShift": {
    "service": "PdfShift",
    "category": "HTML to PDF Conversion",
    "impact": "Unauthorized access to and utilization of the PDF conversion service, potentially leading to excessive API usage charges or the generation of unauthorized PDF documents from sensitive HTML.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed PdfShift API key.\n2. Attempt to convert HTML content to a PDF document using the PdfShift API with the found key.\n3. Verify successful PDF generation.",
    "remediation": "Rotate the PdfShift API key immediately."
  },
  "PeopleDataLabs": {
    "service": "PeopleDataLabs",
    "category": "Person & Company Data API",
    "impact": "Unauthorized access to person and company data, potentially leading to excessive API usage charges or data scraping for lead generation, background checks, or identity theft.",
    "severity": "High",
    "poc_template": "1. Locate exposed PeopleDataLabs API key.\n2. Use the key to enrich a profile with additional person or company data via the PeopleDataLabs API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the PeopleDataLabs API key immediately."
  },
  "Pepipost": {
    "service": "Pepipost",
    "category": "Email Delivery Service",
    "impact": "Unauthorized sending and tracking of emails through Pepipost's infrastructure, potentially leading to spamming, phishing attacks, or resource abuse.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Pepipost API keys.\n2. Attempt to send a test email via the Pepipost API with the found keys.\n3. Verify successful email delivery.",
    "remediation": "Revoke and regenerate the Pepipost API keys immediately. Review Pepipost logs for unauthorized email sending."
  },
  "Percy": {
    "service": "Percy",
    "category": "Visual Testing & Review Platform",
    "impact": "Unauthorized access to and management of visual testing projects, potentially leading to injection of false visual test results, manipulation of UI review processes, or exposure of sensitive UI designs.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Percy token.\n2. Attempt to list projects or upload new visual snapshots using the Percy API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Percy token immediately."
  },
  "Pinata": {
    "service": "Pinata",
    "category": "IPFS File Management",
    "impact": "Unauthorized pinning and management of files on the IPFS network, potentially leading to unauthorized data storage, content manipulation, or resource abuse on the IPFS network.",
    "severity": "High",
    "poc_template": "1. Locate exposed Pinata API keys.\n2. Attempt to pin a new file or list existing pins using the Pinata API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Pinata API keys immediately."
  },
  "Pipedream": {
    "service": "Pipedream",
    "category": "Integration Platform (Workflows)",
    "impact": "Unauthorized access to and modification of workflows and data, potentially leading to unauthorized execution of integrations, data exfiltration from connected applications, or disruption of automated processes.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Pipedream API keys.\n2. Attempt to list workflows, trigger a workflow, or access workflow data using the Pipedream API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Pipedream API keys immediately. Review workflow logs for any unauthorized activities."
  },
  "Pipedrive": {
    "service": "Pipedrive",
    "category": "Sales-focused CRM",
    "impact": "Unauthorized access to and manipulation of CRM data, including deals, contacts, and sales activities, potentially leading to data breaches, lead manipulation, or exposure of sensitive sales information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Pipedrive API token.\n2. Attempt to list deals, add contacts, or modify sales activities using the Pipedrive API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the exposed Pipedrive API token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "PivotalTracker": {
    "service": "PivotalTracker",
    "category": "Project Management Tool",
    "impact": "Unauthorized access to and management of projects and data within PivotalTracker, potentially leading to project disruption, data theft, or exposure of sensitive project details.",
    "severity": "High",
    "poc_template": "1. Locate exposed PivotalTracker tokens.\n2. Attempt to list projects, create stories, or modify tasks using the PivotalTracker API with the found tokens.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the PivotalTracker tokens immediately."
  },
  "Pixabay": {
    "service": "Pixabay",
    "category": "Stock Media Website",
    "impact": "Unauthorized access to and retrieval of photos, illustrations, vector graphics, and film footage, potentially leading to excessive API usage charges or data scraping of media content.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Pixabay API key.\n2. Use the key to search for images or videos via the Pixabay API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Pixabay API key immediately."
  },
  "PlaidKey": {
    "service": "Plaid",
    "category": "Financial Services API",
    "impact": "Unauthorized access to and management of users' bank account financial data, potentially leading to financial fraud, data exfiltration of sensitive banking information, or unauthorized transaction initiation.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Plaid API keys.\n2. Attempt to link a test bank account or retrieve transaction data using the Plaid API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Plaid API keys immediately. Review all connected accounts and transaction logs for unauthorized activity."
  },
  "PlanetScale": {
    "service": "PlanetScale",
    "category": "Database Platform",
    "impact": "Unauthorized access to and management of database instances, potentially leading to data compromise, data exfiltration, injection of malicious queries, or denial of service for the database.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed PlanetScale tokens.\n2. Attempt to list databases, connect to a database, or perform queries using the PlanetScale API or CLI with the found tokens.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the PlanetScale tokens immediately. Review database logs for unauthorized access or changes."
  },
  "PlanetScaleDb": {
    "service": "PlanetScaleDB",
    "category": "Serverless Database Platform",
    "impact": "Unauthorized connection to the database and performance of operations, potentially leading to complete data compromise, data exfiltration, injection of malicious data, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed PlanetScaleDB credentials (connection string containing username/password/host).\n2. Attempt to connect to the database using a database client with the found credentials.\n3. Verify successful connection and attempt to query/modify sensitive tables.",
    "remediation": "Immediately rotate PlanetScaleDB credentials and ensure connection strings are not exposed. Implement strong access controls and network segmentation for database connections."
  },
  "PlanviewLeanKit": {
    "service": "Planview LeanKit",
    "category": "Visual Project Delivery Tool",
    "impact": "Unauthorized access to and management of LeanKit accounts, potentially leading to project disruption, data theft, or exposure of sensitive project management information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Planview LeanKit credential.\n2. Attempt to list boards, modify cards, or access user data using the LeanKit API with the found credential.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the exposed Planview LeanKit credential immediately and generate a new one."
  },
  "Planyo": {
    "service": "Planyo",
    "category": "Online Reservation System",
    "impact": "Unauthorized access to and modification of reservation data, potentially leading to booking manipulation, access to customer information, or financial fraud related to reservations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Planyo API keys.\n2. Attempt to search for reservations, create new bookings, or modify existing reservation data using the Planyo API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Planyo API keys immediately. Review all reservation logs for unauthorized activity."
  },
  "Plivo": {
    "service": "Plivo",
    "category": "Cloud Communications Platform",
    "impact": "Unauthorized access to and management of voice and messaging services, potentially leading to unauthorized message sending, phone call manipulation, or resource abuse.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Plivo credentials (Auth ID and Auth Token).\n2. Attempt to send a test SMS message or initiate a voice call using the Plivo API with the found credentials.\n3. Verify successful message delivery/call initiation.",
    "remediation": "Revoke and regenerate the Plivo credentials immediately. Review Plivo logs for unauthorized activity."
  },
  "Podio": {
    "service": "Podio",
    "category": "Intranet Communication Platform",
    "impact": "Unauthorized access to read sensitive data, potentially leading to data breaches, exposure of internal communications, or access to proprietary project information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Podio API keys.\n2. Attempt to read sensitive data (e.g., workspaces, items) from a Podio account using the Podio API with the found keys.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Podio API keys immediately."
  },
  "PollsAPI": {
    "service": "PollsAPI",
    "category": "Poll Creation & Management",
    "impact": "Unauthorized access to and modification of poll data, potentially leading to poll manipulation, injection of false votes, or exposure of sensitive survey results.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed PollsAPI keys.\n2. Attempt to create a new poll, vote on a poll, or retrieve poll results using the PollsAPI with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Rotate the PollsAPI keys immediately."
  },
  "Poloniex": {
    "service": "Poloniex",
    "category": "Cryptocurrency Exchange",
    "impact": "Unauthorized access to and management of account data and performance of trading operations, potentially leading to unauthorized cryptocurrency trades, fund transfers, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Poloniex API keys.\n2. Attempt to retrieve account balance or place an order using the Poloniex API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Poloniex API keys immediately and enable appropriate security measures like IP whitelisting."
  },
  "Polygon": {
    "service": "Polygon",
    "category": "Blockchain Network (Ethereum-compatible)",
    "impact": "Unauthorized interaction with Polygon's services and access to blockchain data, potentially leading to excessive API usage charges, monitoring of on-chain activity, or unauthorized execution of blockchain functions.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Polygon API key.\n2. Use the key to fetch blockchain data (e.g., transaction history, token balances) via a Polygon RPC endpoint.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Polygon API key immediately."
  },
  "Portainer": {
    "service": "Portainer",
    "category": "Container Management UI",
    "impact": "Unauthorized access to and control over Docker, Docker Swarm, Kubernetes, and Azure ACI environments, potentially leading to unauthorized container deployments, image manipulation, or full compromise of containerized applications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Portainer API tokens.\n2. Attempt to list environments, deploy containers, or modify existing containers using the Portainer API with the found tokens.\n3. Verify successful administrative action.",
    "remediation": "Revoke and regenerate the Portainer API tokens immediately. Review Portainer audit logs for any unauthorized activities."
  },
  "PortainerToken": {
    "service": "Portainer",
    "category": "Container Management UI",
    "impact": "Unauthorized authentication and interaction with the Portainer API, potentially leading to full control over Docker environments, allowing for unauthorized container deployments, image manipulation, or compromise of containerized applications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Portainer token.\n2. Attempt to list environments, deploy containers, or modify existing containers using the Portainer API with the found token.\n3. Verify successful administrative action.",
    "remediation": "Revoke the exposed Portainer token immediately and generate a new one."
  },
  "PositionStack": {
    "service": "PositionStack",
    "category": "Geocoding API",
    "impact": "Unauthorized access to geocoding services, potentially leading to excessive API usage charges or data scraping of location data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed PositionStack API key.\n2. Use the key to perform a forward or reverse geocoding query via the PositionStack API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the PositionStack API key immediately."
  },
  "PostageApp": {
    "service": "PostageApp",
    "category": "Email Sending Service",
    "impact": "Unauthorized sending of emails via their API and access to account information, potentially leading to spamming, phishing attacks, or resource abuse.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed PostageApp API keys.\n2. Attempt to send a test email using the PostageApp API with the found keys.\n3. Verify successful email delivery.",
    "remediation": "Revoke and regenerate the PostageApp API keys immediately. Review PostageApp logs for unauthorized email sending."
  },
  "Postbacks": {
    "service": "Postback URL",
    "category": "Tracking & Analytics",
    "impact": "Unauthorized sending of data to a specified URL based on certain events or triggers, potentially leading to data injection, service disruption, or misuse in affiliate marketing/ad tracking.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Postback URL.\n2. Construct a test payload and send a POST/GET request to the Postback URL.\n3. Verify that the data is received by the intended service or that an event is triggered.",
    "remediation": "If the Postback URL contains sensitive information, regenerate it. Implement strong validation on the receiving end to prevent data injection. Review any services configured to receive postbacks."
  },
  "Postgres": {
    "service": "PostgreSQL",
    "category": "Relational Database",
    "impact": "Unauthorized access to and manipulation of the database, potentially leading to complete data compromise, data exfiltration, injection of malicious queries, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed PostgreSQL connection string (containing username/password/host/database).\n2. Attempt to connect to the PostgreSQL instance using a database client (e.g., psql, DBeaver) with the found credentials.\n3. Verify successful connection and attempt to query/modify sensitive tables.",
    "remediation": "Immediately rotate PostgreSQL credentials and ensure connection strings are not exposed. Implement strong access controls, network segmentation, and encryption for database connections."
  },
  "PosthogApp": {
    "service": "PostHog",
    "category": "Product Analytics Platform",
    "impact": "Unauthorized authentication and tracking of events in PostHog, potentially leading to injection of false analytics, data exfiltration of sensitive event information, or disruption of data visualization.",
    "severity": "High",
    "poc_template": "1. Locate exposed PostHog `phx_` keys.\n2. Attempt to send new events or query existing event data using the PostHog API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed PostHog `phx_` keys immediately and generate new ones."
  },
  "Postman": {
    "service": "Postman",
    "category": "API Development Platform",
    "impact": "Unauthorized access to and modification of collections, environments, and other resources, potentially leading to exposure of API configurations, sensitive environment variables, or disruption of API development workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Postman API key.\n2. Configure Postman CLI or use the Postman API with the found key.\n3. Attempt to list collections, export environments, or modify API requests.\n4. Verify successful access and resource manipulation.",
    "remediation": "Revoke the exposed Postman API key immediately and generate a new one."
  },
  "Postmark": {
    "service": "Postmark",
    "category": "Email Delivery Service",
    "impact": "Unauthorized access to and management of email delivery and statistics, potentially leading to spamming, phishing attacks, or resource abuse.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Postmark server token.\n2. Attempt to send a test email via the Postmark API with the found token.\n3. Verify successful email delivery.",
    "remediation": "Revoke the exposed Postmark server token immediately and generate a new one. Review Postmark logs for unauthorized email sending."
  },
  "Powrbot": {
    "service": "Powrbot",
    "category": "Company Information Service",
    "impact": "Unauthorized access to and retrieval of company information, potentially leading to excessive API usage charges or data scraping of proprietary business data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Powrbot API key.\n2. Use the key to search for company information via the Powrbot API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Powrbot API key immediately."
  },
  "Prefect": {
    "service": "Prefect",
    "category": "Workflow Orchestration Tool",
    "impact": "Unauthorized access to and management of workflows and tasks, potentially leading to unauthorized workflow execution, data manipulation within tasks, or disruption of automated processes.",
    "severity": "High",
    "poc_template": "1. Locate exposed Prefect API key.\n2. Attempt to list flows, run a flow, or access task run logs using the Prefect API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Prefect API key immediately."
  },
  "Privacy": {
    "service": "Privacy.com",
    "category": "Virtual Card Service",
    "impact": "Unauthorized management and creation of virtual cards for secure online payments, potentially leading to financial fraud, unauthorized transactions, or exposure of sensitive payment details.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Privacy API keys.\n2. Attempt to list virtual cards, create a new virtual card, or retrieve transaction details using the Privacy API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Privacy API keys immediately. Review all virtual card activity for unauthorized transactions."
  },
  "PrivateKey": {
    "service": "Generic Private Key",
    "category": "Authentication & Authorization",
    "impact": "Unauthorized access to various systems and services for which this key provides authentication. This could include SSH access to servers, API authentication, code signing, or decrypting sensitive data, leading to full system compromise, data exfiltration, or impersonation.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Private Key (e.g., SSH key, API key, cryptographic key).\n2. Attempt to use the key to authenticate to a known system or service (e.g., SSH into a server, sign a commit, decrypt a file).\n3. Verify successful unauthorized access or action.",
    "remediation": "Immediately revoke and replace the compromised private key wherever it is used. Implement strong key management practices, including key rotation, least privilege, and secure storage."
  },
  "Prodpad": {
    "service": "Prodpad",
    "category": "Product Management Tool",
    "impact": "Unauthorized access to and modification of product data and configurations, potentially leading to manipulation of product roadmaps, exposure of sensitive product strategies, or disruption of product development workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Prodpad API key.\n2. Attempt to list products, create ideas, or modify product details using the Prodpad API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Prodpad API key immediately."
  },
  "ProspectCRM": {
    "service": "ProspectCRM",
    "category": "Customer Relationship Management System",
    "impact": "Unauthorized access to and management of customer data, potentially leading to data breaches, lead manipulation, or exposure of sensitive customer information.",
    "severity": "High",
    "poc_template": "1. Locate exposed ProspectCRM API keys.\n2. Attempt to list or modify customer records or sales opportunities using the ProspectCRM API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the ProspectCRM API keys immediately."
  },
  "ProtocolsIO": {
    "service": "Protocols.io",
    "category": "Research Protocol Platform",
    "impact": "Unauthorized access to and management of research protocols and data, potentially leading to intellectual property theft, content tampering, or exposure of sensitive scientific research.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Protocols.io API keys.\n2. Attempt to list protocols or access protocol details using the Protocols.io API with the found keys.\n3. Verify successful data access.",
    "remediation": "Rotate the Protocols.io API keys immediately."
  },
  "ProxyCrawl": {
    "service": "ProxyCrawl",
    "category": "Web Scraping & Crawling",
    "impact": "Unauthorized access to and control over web scraping and crawling capabilities, potentially leading to excessive API usage charges, unauthorized data extraction from websites, or misuse of proxy networks.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ProxyCrawl tokens.\n2. Attempt to perform a web scrape or use a proxy via the ProxyCrawl API with the found tokens.\n3. Verify successful API interaction.",
    "remediation": "Rotate the ProxyCrawl tokens immediately."
  },
  "PubNubPublishKey": {
    "service": "PubNub",
    "category": "Real-time Communication Platform",
    "impact": "Unauthorized sending of messages to channels, potentially leading to spamming, injection of false data into real-time streams, or disruption of communication channels.",
    "severity": "High",
    "poc_template": "1. Locate exposed PubNub Publish Key.\n2. Use the key to publish a message to a PubNub channel.\n3. Verify that the message appears in the channel (requires a corresponding subscribe key or monitoring tool).",
    "remediation": "Revoke the exposed PubNub Publish Key immediately and generate a new one. Implement robust channel access control."
  },
  "PubNubSubscriptionKey": {
    "service": "PubNub",
    "category": "Real-time Communication Platform",
    "impact": "Unauthorized access to subscribe to channels and receive messages, potentially leading to eavesdropping on sensitive real-time communications or data exfiltration from real-time streams.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed PubNub Subscription Key.\n2. Use the key to subscribe to a PubNub channel and receive messages.\n3. Verify successful message reception.",
    "remediation": "Revoke the exposed PubNub Subscription Key immediately and generate a new one. Implement robust channel access control."
  },
  "Pulumi": {
    "service": "Pulumi",
    "category": "Infrastructure as Code (IaC)",
    "impact": "Unauthorized management of cloud infrastructure and services, potentially leading to unauthorized resource creation/deletion, privilege escalation, data breaches, or complete environment compromise.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Pulumi API key.\n2. Configure Pulumi CLI with the found key.\n3. Attempt to list stacks, create new resources, or modify existing infrastructure deployments.\n4. Verify successful administrative control over cloud resources.",
    "remediation": "Immediately revoke the exposed Pulumi API key and generate a new one. Implement strong access controls, review Pulumi audit logs for unauthorized changes, and consider using short-lived tokens or secrets management solutions."
  },
  "PureStake": {
    "service": "PureStake",
    "category": "Blockchain Infrastructure Provider",
    "impact": "Unauthorized interaction with the Algorand blockchain network, potentially leading to excessive API usage charges, monitoring of on-chain activity, or unauthorized transaction submissions.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed PureStake API keys.\n2. Use the keys to fetch blockchain data (e.g., account balance, transaction details) from the Algorand network via the PureStake API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the PureStake API keys immediately."
  },
  "PushBulletApiKey": {
    "service": "Pushbullet",
    "category": "Notification Service",
    "impact": "Unauthorized interaction with the Pushbullet API to send and receive notifications, potentially leading to spamming, unauthorized message sending, or access to sensitive notification content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Pushbullet API key.\n2. Attempt to send a test notification ('push') or list devices using the Pushbullet API with the found key.\n3. Verify successful notification delivery.",
    "remediation": "Revoke the exposed Pushbullet API key immediately and generate a new one."
  },
  "PusherChannelKey": {
    "service": "Pusher",
    "category": "Real-time Functionality Service",
    "impact": "Unauthorized authentication and sending of messages to channels, potentially leading to spamming, injection of false data into real-time streams, or disruption of communication channels.",
    "severity": "High",
    "poc_template": "1. Locate exposed Pusher Channel key.\n2. Use the key to publish a message to a Pusher channel.\n3. Verify that the message appears in the channel (requires a corresponding Pusher client or subscription).",
    "remediation": "Revoke the exposed Pusher Channel key immediately and generate a new one. Implement robust channel access control."
  },
  "PyPI": {
    "service": "PyPI (Python Package Index)",
    "category": "Software Repository (Python)",
    "impact": "Unauthorized management of PyPI packages, potentially leading to supply chain attacks (injecting malicious code into widely used Python packages), package deletion, or unauthorized access to private packages.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed PyPI credentials (e.g., API token).\n2. Configure `twine` or another PyPI client with the found credential.\n3. Attempt to upload a new package, update an existing package, or list projects associated with the account.\n4. Verify successful package manipulation.",
    "remediation": "Immediately revoke the exposed PyPI credential through your PyPI account settings. Enable two-factor authentication for your PyPI account and audit any packages published or modified."
  }
}




























{
  "Qase": {
    "service": "Qase",
    "category": "Test Management Platform",
    "impact": "Unauthorized access to and modification of test data and settings, potentially leading to manipulation of test cases, plans, and runs, affecting software quality and release cycles, or exposing sensitive testing information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Qase API token.\n2. Attempt to list test cases, create a new test run, or modify project settings using the Qase API with the found token.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the exposed Qase API token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Qualaroo": {
    "service": "Qualaroo",
    "category": "Customer Survey Tool",
    "impact": "Unauthorized access to and management of survey data, potentially leading to exposure of sensitive customer feedback, manipulation of survey results, or disruption of feedback collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Qualaroo API key.\n2. Attempt to list surveys or retrieve feedback data using the Qualaroo API with the found key.\n3. Verify successful data access.",
    "remediation": "Rotate the Qualaroo API key immediately."
  },
  "Qubole": {
    "service": "Qubole",
    "category": "Cloud-based Data Platform",
    "impact": "Unauthorized access to and management of data processing, management, and analytics services, potentially leading to data compromise, resource abuse, or disruption of critical data workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Qubole API keys.\n2. Attempt to list clusters, submit a data query, or manage data workflows using the Qubole API with the found keys.\n3. Verify successful administrative access and resource manipulation.",
    "remediation": "Revoke and regenerate the Qubole API keys immediately. Implement strong access controls and review Qubole audit logs for unauthorized activities."
  },
  "RabbitMQ": {
    "service": "RabbitMQ",
    "category": "Message Broker",
    "impact": "Unauthorized access to and management of message queues, potentially leading to interception of sensitive messages, injection of malicious messages, or denial of service by flooding queues.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed RabbitMQ credentials (username/password).\n2. Attempt to connect to the RabbitMQ management interface or directly to a queue using a client library with the found credentials.\n3. Verify successful connection and attempt to list queues, publish messages, or consume messages from a queue.",
    "remediation": "Immediately rotate RabbitMQ credentials. Ensure strong, unique passwords are used and implement robust access control policies. Review RabbitMQ logs for unauthorized access."
  },
  "RailwayApp": {
    "service": "Railway",
    "category": "Deployment Platform",
    "impact": "Unauthorized access to and management of deployments, CI/CD integrations, and observability features, potentially leading to unauthorized code deployments, service disruptions, or access to sensitive application data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Railway API keys/tokens.\n2. Attempt to list projects, deploy new services, or access environment variables using the Railway API/CLI with the found credentials.\n3. Verify successful administrative control.",
    "remediation": "Immediately revoke the exposed Railway API keys/tokens and generate new ones, ensuring they have minimal necessary permissions and a short lifespan."
  },
  "Ramp": {
    "service": "Ramp",
    "category": "Financial Services (Expense Management)",
    "impact": "Unauthorized access to and management of financial services, including expense management and corporate cards, potentially leading to financial fraud, unauthorized spending, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Ramp credentials.\n2. Attempt to list transactions, manage corporate cards, or access financial reports via the Ramp API.\n3. Verify successful administrative access and financial data manipulation.",
    "remediation": "Immediately revoke the exposed Ramp credentials and generate new ones. Implement strong access controls and multi-factor authentication. Review all audit logs for unauthorized activities."
  },
  "RapidApi": {
    "service": "RapidAPI",
    "category": "API Marketplace",
    "impact": "Unauthorized access to and interaction with thousands of APIs connected through the platform, potentially leading to excessive API usage charges, access to data from various third-party services, or resource abuse depending on the connected APIs.",
    "severity": "High",
    "poc_template": "1. Locate exposed RapidAPI key.\n2. Attempt to make a request to a connected API (e.g., a data service, a utility API) using the RapidAPI endpoint with the found key.\n3. Verify successful API interaction and data retrieval.",
    "remediation": "Revoke the exposed RapidAPI key immediately and generate a new one. Review usage logs for any unauthorized API calls."
  },
  "Rawg": {
    "service": "RAWG",
    "category": "Video Game Database",
    "impact": "Unauthorized access to video game data and related services, potentially leading to excessive API usage charges or data scraping of game information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed RAWG API key.\n2. Use the key to fetch game details or search for games via the RAWG API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the RAWG API key immediately."
  },
  "RazorPay": {
    "service": "RazorPay",
    "category": "Payment Gateway Service",
    "impact": "Unauthorized access to and management of payment transactions, potentially leading to financial fraud, unauthorized payment processing, or exposure of sensitive payment and customer data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed RazorPay keys (Client ID and Client Secret).\n2. Attempt to retrieve transaction details or initiate a payment using the RazorPay API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke and regenerate the RazorPay keys. Review all transaction logs and webhook notifications for unauthorized activity."
  },
  "Reachmail": {
    "service": "Reachmail",
    "category": "Email Marketing Service",
    "impact": "Unauthorized access to and management of email marketing campaigns and user data, potentially leading to unauthorized email sending, spamming, or exposure of sensitive subscriber lists.",
    "severity": "High",
    "poc_template": "1. Locate exposed Reachmail API keys.\n2. Attempt to list campaigns or add contacts using the Reachmail API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Reachmail API keys immediately."
  },
  "ReadMe": {
    "service": "ReadMe",
    "category": "Documentation Platform",
    "impact": "Unauthorized access to and modification of API and product documentation, potentially leading to unauthorized content publishing, content tampering, or exposure of sensitive product information.",
    "severity": "High",
    "poc_template": "1. Locate exposed ReadMe API key.\n2. Attempt to list documentation pages or create a new guide using the ReadMe API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the exposed ReadMe API key and generate a new one immediately. Review ReadMe audit logs for any unauthorized changes."
  },
  "ReallySimpleSystems": {
    "service": "ReallySimpleSystems",
    "category": "CRM System",
    "impact": "Unauthorized access to and management of customer relationship data and workflows, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "High",
    "poc_template": "1. Locate exposed ReallySimpleSystems credentials.\n2. Attempt to list or modify customer records or sales opportunities using the ReallySimpleSystems API with the found credentials.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the ReallySimpleSystems credentials immediately."
  },
  "Rebrandly": {
    "service": "Rebrandly",
    "category": "Link Management Platform",
    "impact": "Unauthorized management and analysis of short URLs, potentially leading to the creation of malicious short links (e.g., for phishing), redirection of traffic, or exposure of sensitive link click data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Rebrandly API key.\n2. Attempt to create a new branded link or retrieve analytics for an existing one using the Rebrandly API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Rebrandly API key immediately."
  },
  "RechargePayments": {
    "service": "Recharge",
    "category": "Subscription Payment Solution",
    "impact": "Unauthorized access to and management of subscription data and transactions, potentially leading to financial fraud, unauthorized subscription modifications, or exposure of sensitive customer billing information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Recharge API keys.\n2. Attempt to retrieve customer subscriptions, modify recurring orders, or access payment source data using the Recharge API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Recharge API keys immediately. Review all transaction and subscription logs for unauthorized activity."
  },
  "Redis": {
    "service": "Redis",
    "category": "In-memory Data Store",
    "impact": "Unauthorized access to and manipulation of stored data, potentially leading to data theft, data corruption, or denial of service. Redis often stores session data, caches, or message queues, making it a critical target.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Redis credentials (host, port, password/ACL token).\n2. Attempt to connect to the Redis instance using a Redis client (e.g., `redis-cli`, Python `redis` library) with the found credentials.\n3. Verify successful connection and attempt to read, write, or delete keys (e.g., `GET <key>`, `SET <key> <value>`, `DEL <key>`).",
    "remediation": "Immediately rotate Redis passwords/ACL tokens. Ensure Redis instances are not exposed to the internet, implement strong ACLs (Access Control Lists), and consider using SSL/TLS for connections. Audit Redis logs for unauthorized access."
  },
  "Refiner": {
    "service": "Refiner",
    "category": "User Feedback Platform",
    "impact": "Unauthorized authentication and identification of users within the Refiner platform, potentially leading to manipulation of user feedback, injection of false survey responses, or access to sensitive user data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Refiner keys.\n2. Attempt to track user events or retrieve user segments using the Refiner API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Refiner keys immediately."
  },
  "Rentman": {
    "service": "Rentman",
    "category": "Resource Management (AV & Event)",
    "impact": "Unauthorized access to and management of resources and data within the Rentman platform, including equipment scheduling, time tracking, and project management, potentially leading to resource misallocation, financial fraud, or exposure of sensitive event production data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Rentman API key.\n2. Attempt to list equipment, modify bookings, or access project schedules using the Rentman API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Rentman API key immediately."
  },
  "Repairshopr": {
    "service": "RepairShopr",
    "category": "CRM & Ticketing System",
    "impact": "Unauthorized access to and management of appointments, customers, invoices, and other CRM functionalities, potentially leading to data breaches, financial fraud, or disruption of repair shop operations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed RepairShopr API keys.\n2. Attempt to list customers, create tickets, or access invoice data using the RepairShopr API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the RepairShopr API keys immediately. Review all API activity for unauthorized changes."
  },
  "Replicate": {
    "service": "Replicate",
    "category": "Machine Learning Model Platform",
    "impact": "Unauthorized management and running of machine learning models in the cloud, potentially leading to excessive API usage charges, unauthorized model execution, or exposure of sensitive model inputs/outputs.",
    "severity": "High",
    "poc_template": "1. Locate exposed Replicate API key.\n2. Attempt to list models or run an inference using the Replicate API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Replicate API key immediately."
  },
  "ReplyIO": {
    "service": "Reply.io",
    "category": "Sales Engagement Platform",
    "impact": "Unauthorized access to and management of communication data, potentially leading to unauthorized email sending, exposure of sensitive prospect interactions, or disruption of sales outreach campaigns.",
    "severity": "High",
    "poc_template": "1. Locate exposed Reply.io API key.\n2. Attempt to list prospects, send a test email, or retrieve sequence data using the Reply.io API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Reply.io API key immediately."
  },
  "RequestFinance": {
    "service": "Request Finance",
    "category": "Invoice & Payment Automation",
    "impact": "Unauthorized access to and management of invoices and payments, potentially leading to financial fraud, unauthorized payment initiation, or exposure of sensitive financial records.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Request Finance credentials.\n2. Attempt to create an invoice, retrieve payment status, or access financial details via the Request Finance API.\n3. Verify successful administrative access and financial data manipulation.",
    "remediation": "Immediately revoke the exposed Request Finance credentials and generate new ones. Implement strong access controls and review all audit logs for unauthorized activities."
  },
  "RestpackHtmlToPdfAPI": {
    "service": "Restpack (HTML to PDF API)",
    "category": "Document Conversion",
    "impact": "Unauthorized access to and utilization of the HTML to PDF conversion service, potentially leading to excessive API usage charges or the generation of unauthorized PDF documents from sensitive HTML.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Restpack API key.\n2. Attempt to convert HTML content to a PDF document using the Restpack HTML to PDF API with the found key.\n3. Verify successful PDF generation.",
    "remediation": "Rotate the Restpack API key immediately."
  },
  "RestpackScreenshotAPI": {
    "service": "Restpack Screenshot API",
    "category": "Screenshot Service",
    "impact": "Unauthorized authentication to capture screenshots of web pages, potentially leading to excessive API usage charges or the capture of sensitive internal web pages without authorization.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Restpack Screenshot API key.\n2. Use the key to generate a screenshot of a public webpage via the Restpack Screenshot API.\n3. Verify successful screenshot generation.",
    "remediation": "Rotate the Restpack Screenshot API key immediately."
  },
  "RevampCRM": {
    "service": "RevampCRM",
    "category": "Customer Relationship Management",
    "impact": "Unauthorized access to and management of customer data, potentially leading to data breaches, lead manipulation, or exposure of sensitive customer information.",
    "severity": "High",
    "poc_template": "1. Locate exposed RevampCRM credentials.\n2. Attempt to list or modify customer records or sales opportunities using the RevampCRM API with the found credentials.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the RevampCRM credentials immediately."
  },
  "RingCentral": {
    "service": "RingCentral",
    "category": "Cloud Communication System",
    "impact": "Unauthorized access to and management of messaging, video conferencing, and phone services, potentially leading to unauthorized calls/messages, eavesdropping, or disruption of communication systems.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed RingCentral API keys.\n2. Attempt to send a test message, make a call, or access call logs using the RingCentral API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the RingCentral API keys immediately. Review RingCentral audit logs for unauthorized activities."
  },
  "RiteKit": {
    "service": "RiteKit",
    "category": "Social Media Toolkit",
    "impact": "Unauthorized access to various APIs for managing social media content and analytics, potentially leading to unauthorized social media posting, data scraping of analytics, or misuse of social media tools.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed RiteKit API keys.\n2. Use the keys to generate hashtags, analyze tweets, or access other social media data via the RiteKit API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the RiteKit API keys immediately."
  },
  "Roaring": {
    "service": "Roaring",
    "category": "High-Performance Data Services",
    "impact": "Unauthorized access to the Roaring API, which provides services for high-performance, compressed bitmaps, potentially leading to data exfiltration or resource abuse related to large datasets.",
    "severity": "High",
    "poc_template": "1. Locate exposed Roaring credentials.\n2. Attempt to make a request to the Roaring API (e.g., query bitmap data) using the found credentials.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Roaring credentials immediately."
  },
  "RobinhoodCrypto": {
    "service": "Robinhood Crypto",
    "category": "Cryptocurrency Trading Platform",
    "impact": "Unauthorized access to and trading of cryptocurrencies on the Robinhood platform, potentially leading to unauthorized trades, fund manipulation, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Robinhood Crypto API keys.\n2. Attempt to retrieve account balance or place a cryptocurrency trade using the Robinhood Crypto API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Robinhood Crypto API keys immediately and implement appropriate security measures like 2FA and strong passwords for the Robinhood account."
  },
  "RocketReach": {
    "service": "RocketReach",
    "category": "Professional Contact Finder",
    "impact": "Unauthorized access to and retrieval of email addresses, phone numbers, and social media profiles for professionals, potentially leading to excessive API usage charges or data scraping for lead generation or reconnaissance.",
    "severity": "High",
    "poc_template": "1. Locate exposed RocketReach API key.\n2. Use the key to search for contact information for a professional via the RocketReach API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the RocketReach API key immediately."
  },
  "RoninApp": {
    "service": "RoninApp",
    "category": "Online Invoicing & Time Tracking",
    "impact": "Unauthorized access to and management of invoices and other resources, potentially leading to financial fraud, inaccurate invoicing, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed RoninApp keys.\n2. Attempt to retrieve or modify invoice data or time entries using the RoninApp API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the RoninApp keys immediately."
  },
  "Route4me": {
    "service": "Route4Me",
    "category": "Route Planning Service",
    "impact": "Unauthorized access to and modification of routing data and services, potentially leading to disruption of delivery/service fleet operations, exposure of sensitive route information, or resource abuse.",
    "severity": "High",
    "poc_template": "1. Locate exposed Route4Me API keys.\n2. Attempt to create a route, optimize an existing route, or retrieve route data using the Route4Me API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Route4Me API keys immediately."
  },
  "Rownd": {
    "service": "Rownd",
    "category": "User Data Management",
    "impact": "Unauthorized access to and modification of user data and application settings, potentially leading to data breaches, user profile manipulation, or disruption of identity and access management functionalities.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Rownd credentials.\n2. Attempt to list users, modify user attributes, or access application settings using the Rownd API with the found credentials.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Rownd credentials immediately. Review Rownd audit logs for any unauthorized activities."
  },
  "RubyGems": {
    "service": "RubyGems",
    "category": "Package Manager (Ruby)",
    "impact": "Unauthorized publishing and management of gems (libraries) on the RubyGems platform, potentially leading to supply chain attacks (injecting malicious code into widely used Ruby gems), gem deletion, or unauthorized access to private gems.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed RubyGems API key.\n2. Configure RubyGems CLI (`gem push`) with the found key.\n3. Attempt to push a new gem, update an existing gem, or list gems associated with the account.\n4. Verify successful gem manipulation.",
    "remediation": "Immediately revoke the exposed RubyGems API key through your RubyGems.org account settings. Enable two-factor authentication for your RubyGems account and audit any gems published or modified."
  },
  "RunRunIt": {
    "service": "RunRunIt",
    "category": "Project Management Tool",
    "impact": "Unauthorized access to and modification of project data, potentially leading to project disruption, data theft, or exposure of sensitive project details.",
    "severity": "High",
    "poc_template": "1. Locate exposed RunRunIt App-Key and User-Token.\n2. Attempt to list projects or modify tasks using the RunRunIt API with the found credentials.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the RunRunIt App-Key and User-Token immediately."
  },
  "SQLServer": {
    "service": "SQL Server",
    "category": "Relational Database Management System",
    "impact": "Unauthorized access to and management of databases, potentially leading to complete data compromise, data exfiltration, injection of malicious queries, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed SQL Server credentials (connection string containing username/password/host/database).\n2. Attempt to connect to the SQL Server instance using a database client (e.g., SQL Server Management Studio, Azure Data Studio) with the found credentials.\n3. Verify successful connection and attempt to query/modify sensitive tables.",
    "remediation": "Immediately rotate SQL Server credentials. Ensure SQL Server is not exposed to the internet, implement strong access controls, and use encryption for database connections. Review SQL Server logs for unauthorized access."
  },
  "SaladCloudApiKey": {
    "service": "SaladCloud",
    "category": "Cloud Service Provider (GPU/NPU Computing)",
    "impact": "Unauthorized access to and modification of compute and data resources, potentially leading to unauthorized resource provisioning, cryptocurrency mining, data exfiltration, or billing fraud.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed SaladCloud API key.\n2. Attempt to list compute resources, deploy workloads, or access data storage using the SaladCloud API with the found key.\n3. Verify successful administrative access and resource manipulation.",
    "remediation": "Revoke the exposed SaladCloud API key and generate a new one immediately. Review SaladCloud audit logs for any unauthorized activities."
  },
  "Salesblink": {
    "service": "Salesblink",
    "category": "Sales Outreach Automation",
    "impact": "Unauthorized access to and management of sales outreach campaigns and data, potentially leading to unauthorized email/LinkedIn/cold call outreach, lead theft, or exposure of sensitive sales strategies.",
    "severity": "High",
    "poc_template": "1. Locate exposed Salesblink API keys.\n2. Attempt to list campaigns or add prospects using the Salesblink API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Salesblink API keys immediately."
  },
  "Salescookie": {
    "service": "Salescookie",
    "category": "Sales Performance Management",
    "impact": "Unauthorized creation and management of sales transactions, potentially leading to financial fraud, data manipulation, or exposure of sensitive sales commission data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Salescookie API keys.\n2. Attempt to create a test transaction or retrieve commission data using the Salescookie API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Salescookie API keys immediately."
  },
  "Salesflare": {
    "service": "Salesflare",
    "category": "CRM Tool",
    "impact": "Unauthorized access to and management of customer data and interactions, potentially leading to data breaches, lead manipulation, or exposure of sensitive business relationships.",
    "severity": "High",
    "poc_template": "1. Locate exposed Salesflare API keys.\n2. Attempt to list or modify customer records or deals using the Salesflare API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Salesflare API keys immediately."
  },
  "Salesforce": {
    "service": "Salesforce",
    "category": "Customer Relationship Management (CRM)",
    "impact": "Unauthorized authentication and interaction with Salesforce APIs, potentially leading to full access to customer data, sales records, service cases, or other sensitive business information, enabling data exfiltration or manipulation.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Salesforce access token.\n2. Use the token to make an API request to Salesforce (e.g., query accounts, create leads, update opportunities).\n3. Verify successful data access or manipulation.",
    "remediation": "Immediately revoke the exposed Salesforce access token through Salesforce's Connected Apps OAuth Usage or Setup > Connected Apps OAuth policies. Review Salesforce audit logs for any unauthorized activities."
  },
  "Salesmate": {
    "service": "Salesmate",
    "category": "Customer Relationship Management (CRM)",
    "impact": "Unauthorized access to and management of customer data and interactions, potentially leading to data breaches, lead manipulation, or exposure of sensitive customer information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Salesmate keys.\n2. Attempt to list or modify customer records or sales activities using the Salesmate API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Salesmate keys immediately."
  },
  "Sanity": {
    "service": "Sanity (Modern CMS)",
    "category": "Content Management System",
    "impact": "Unauthorized interaction with CMS content, potentially leading to unauthorized content publishing, content manipulation, or deletion of crucial digital experiences.",
    "severity": "High",
    "poc_template": "1. Locate exposed Sanity API key.\n2. Attempt to create, edit, update, or delete content using the Sanity API with the found key.\n3. Verify successful content manipulation.",
    "remediation": "Revoke the exposed Sanity API key and generate a new one, ensuring it has minimal necessary permissions."
  },
  "SatismeterProjectkey": {
    "service": "Satismeter",
    "category": "Customer Feedback Platform",
    "impact": "Unauthorized access to project-specific data and management of feedback settings, potentially leading to exposure of sensitive customer feedback, manipulation of survey results, or disruption of feedback collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Satismeter project key.\n2. Attempt to retrieve project-specific data or modify feedback settings using the Satismeter API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Satismeter project key immediately."
  },
  "SatismeterWritekey": {
    "service": "Satismeter",
    "category": "Customer Feedback Platform",
    "impact": "Unauthorized sending of event data to Satismeter's API, potentially leading to injection of false feedback, manipulation of survey responses, or resource abuse.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Satismeter Writekey.\n2. Use the key to send a test event or survey response to Satismeter's API.\n3. Verify successful data submission.",
    "remediation": "Rotate the Satismeter Writekey immediately."
  },
  "SauceLabs": {
    "service": "Sauce Labs",
    "category": "Cross-Browser Testing",
    "impact": "Unauthorized creation and access to tests from potentially sensitive internal websites, leading to exposure of internal web application vulnerabilities, data exfiltration from test environments, or resource abuse.",
    "severity": "High",
    "poc_template": "1. Locate exposed Sauce Labs API keys.\n2. Attempt to launch a test on a specified URL (e.g., an internal development URL) or retrieve test results using the Sauce Labs API with the found keys.\n3. Verify successful test execution or data access.",
    "remediation": "Revoke the exposed Sauce Labs API keys and generate new ones immediately. Implement IP whitelisting for API access and ensure test environments are isolated."
  },
  "ScalewayKey": {
    "service": "Scaleway",
    "category": "Cloud Service Provider",
    "impact": "Unauthorized access to and management of cloud services, including virtual instances, storage, and networking, potentially leading to resource abuse, data exfiltration, or denial of service.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Scaleway API key.\n2. Configure Scaleway CLI (`scw`) with the found key.\n3. Attempt to list instances, manage buckets, or modify networking settings.\n4. Verify successful access and resource manipulation.",
    "remediation": "Immediately revoke the exposed Scaleway API key and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Scalr": {
    "service": "Scalr",
    "category": "Cloud Management Platform",
    "impact": "Unauthorized access to and management of cloud infrastructure, potentially leading to unauthorized resource provisioning, data exfiltration, or full compromise of cloud environments.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Scalr keys.\n2. Attempt to list environments, launch new instances, or manage cloud resources using the Scalr API with the found keys.\n3. Verify successful administrative access and resource manipulation.",
    "remediation": "Revoke and regenerate the Scalr keys immediately. Review Scalr audit logs for any unauthorized activities."
  },
  "ScrapeStack": {
    "service": "ScrapeStack",
    "category": "Web Scraping API",
    "impact": "Unauthorized scraping of web data and access to various scraping functionalities, potentially leading to excessive API usage charges or data exfiltration from target websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ScrapeStack API key.\n2. Use the key to perform a web scraping request via the ScrapeStack API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ScrapeStack API key immediately."
  },
  "Scrapeowl": {
    "service": "ScrapeOwl",
    "category": "Web Scraping Service",
    "impact": "Unauthorized automation of data extraction tasks from websites, potentially leading to excessive API usage charges or data exfiltration from target websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ScrapeOwl API key.\n2. Use the key to perform a web scraping request via the ScrapeOwl API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ScrapeOwl API key immediately."
  },
  "ScraperAPI": {
    "service": "ScraperAPI",
    "category": "Web Scraping Service",
    "impact": "Unauthorized access to and scraping of data from various websites, potentially leading to excessive API usage charges or data exfiltration from target websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ScraperAPI key.\n2. Use the key to perform a web scraping request via the ScraperAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ScraperAPI key immediately."
  },
  "ScraperBox": {
    "service": "ScraperBox",
    "category": "Web Scraping Service",
    "impact": "Unauthorized authentication and performance of scraping operations, potentially leading to excessive API usage charges or data exfiltration from target websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ScraperBox token.\n2. Use the token to perform a web scraping request via the ScraperBox API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ScraperBox token immediately."
  },
  "Scrapfly": {
    "service": "Scrapfly",
    "category": "Web Scraping Service",
    "impact": "Unauthorized access to and manipulation of web scraping and data processing, potentially leading to excessive API usage charges or data exfiltration from target websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Scrapfly API key.\n2. Use the key to perform a web scraping request via the Scrapfly API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Scrapfly API key immediately."
  },
  "ScrapingAnt": {
    "service": "ScrapingAnt",
    "category": "Web Scraping Service",
    "impact": "Unauthorized authentication and making of requests to their scraping endpoints, potentially leading to excessive API usage charges or data exfiltration from target websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ScrapingAnt API key.\n2. Use the key to perform a web scraping request via the ScrapingAnt API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ScrapingAnt API key immediately."
  },
  "ScrapingBee": {
    "service": "ScrapingBee",
    "category": "Web Scraping Service",
    "impact": "Unauthorized access to and control over web scraping tasks, including headless browsers and proxies, potentially leading to excessive API usage charges or data exfiltration from target websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ScrapingBee API key.\n2. Use the key to perform a web scraping request via the ScrapingBee API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ScrapingBee API key immediately."
  },
  "ScreenshotAPI": {
    "service": "ScreenshotAPI",
    "category": "Website Screenshot Service",
    "impact": "Unauthorized taking of screenshots of websites, including potentially internal or sensitive websites, potentially leading to exposure of confidential information or excessive API usage charges.",
    "severity": "High",
    "poc_template": "1. Locate exposed ScreenshotAPI key.\n2. Use the key to generate a screenshot of a specified URL (including internal URLs if accessible) via the ScreenshotAPI.\n3. Verify successful screenshot generation and content.",
    "remediation": "Rotate the ScreenshotAPI key immediately. Restrict the domains from which screenshots can be taken if possible."
  },
  "ScreenshotLayer": {
    "service": "ScreenshotLayer",
    "category": "Website Screenshot Service",
    "impact": "Unauthorized capture and retrieval of website screenshots, potentially leading to excessive API usage charges or the capture of sensitive internal web pages without authorization.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ScreenshotLayer access key.\n2. Use the key to capture and retrieve a screenshot of a specified URL via the ScreenshotLayer API.\n3. Verify successful screenshot generation and content.",
    "remediation": "Rotate the ScreenshotLayer access key immediately."
  },
  "ScrutinizerCi": {
    "service": "Scrutinizer CI",
    "category": "Continuous Integration Service",
    "impact": "Unauthorized access to user repositories data, potentially leading to exposure of source code, build logs, or other sensitive CI/CD information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Scrutinizer CI access token.\n2. Attempt to list user repositories or access build data using the Scrutinizer CI API with the found token.\n3. Verify successful data access.",
    "remediation": "Revoke the exposed Scrutinizer CI access token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "SecurityTrails": {
    "service": "SecurityTrails",
    "category": "Domain & IP Intelligence",
    "impact": "Unauthorized access to comprehensive domain and IP intelligence data, potentially leading to excessive API usage charges or data scraping for reconnaissance, cyber intelligence, or competitive analysis.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed SecurityTrails API key.\n2. Use the key to query domain or IP information via the SecurityTrails API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the SecurityTrails API key immediately."
  },
  "SegmentApiKey": {
    "service": "Segment",
    "category": "Customer Data Platform",
    "impact": "Unauthorized access to and management of customer data, including collection, cleaning, and control, potentially leading to data breaches, injection of false customer data, or disruption of data pipelines.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Segment API key.\n2. Attempt to send new customer events, retrieve audience data, or modify data sources using the Segment API with the found key.\n3. Verify successful API interaction and data manipulation.",
    "remediation": "Revoke and regenerate the Segment API key immediately. Review Segment audit logs for any unauthorized activities."
  },
  "SelectPDF": {
    "service": "SelectPDF",
    "category": "Web to PDF Conversion",
    "impact": "Unauthorized conversion of web pages to PDF documents, potentially leading to excessive API usage charges or the generation of unauthorized PDF documents from sensitive web content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed SelectPDF API key.\n2. Attempt to convert a web page URL to a PDF document using the SelectPDF API with the found key.\n3. Verify successful PDF generation.",
    "remediation": "Rotate the SelectPDF API key immediately."
  },
  "Semaphore": {
    "service": "Semaphore",
    "category": "Continuous Integration & Deployment",
    "impact": "Unauthorized access to and management of CI/CD pipelines, potentially leading to unauthorized software deployments, access to build artifacts, or disruption of continuous integration workflows.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Semaphore API keys.\n2. Attempt to list projects, trigger a build, or access build logs using the Semaphore API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Semaphore API keys immediately. Review Semaphore audit logs for unauthorized activities."
  },
  "SendGrid": {
    "service": "SendGrid",
    "category": "Email Delivery & Marketing",
    "impact": "Unauthorized sending of emails and management of other email-related tasks, potentially leading to spamming, phishing attacks, or unauthorized access to email statistics and marketing campaign data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed SendGrid API key.\n2. Attempt to send a test email via the SendGrid API with the found key.\n3. Verify successful email delivery.",
    "remediation": "Revoke the exposed SendGrid API key immediately and generate a new one, ensuring it has minimal necessary permissions (e.g., restricted to sending only if applicable)."
  },
  "Sendbird": {
    "service": "Sendbird",
    "category": "Communication Platform (Chat, Voice, Video)",
    "impact": "Unauthorized access to and management of communication services, potentially leading to unauthorized messaging, eavesdropping on conversations, or disruption of real-time communication features within applications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Sendbird API tokens.\n2. Attempt to list users, send messages, or create channels using the Sendbird API with the found tokens.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Sendbird API tokens immediately. Review Sendbird logs for unauthorized activities."
  },
  "SendbirdOrganizationAPI": {
    "service": "Sendbird",
    "category": "Chat & Messaging Platform",
    "impact": "Unauthorized access to and management of Sendbird applications and services at an organizational level, potentially leading to creating/deleting applications, accessing all user data, or disrupting all communication services within the organization.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Sendbird Organization API token.\n2. Attempt to list applications, create new applications, or manage organization-level settings using the Sendbird Organization API with the found token.\n3. Verify successful administrative action.",
    "remediation": "Immediately revoke the exposed Sendbird Organization API token and generate a new one, ensuring it has strong security practices and is used only when necessary."
  },
  "SendinBlueV2": {
    "service": "SendinBlue (Brevo)",
    "category": "Marketing Communication Software",
    "impact": "Unauthorized access to and modification of marketing campaigns and contact data, potentially leading to unauthorized email/SMS sending, spamming, or exposure of sensitive subscriber lists.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed SendinBlue API key.\n2. Attempt to list contacts, send a test campaign, or modify marketing lists using the SendinBlue API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the SendinBlue API key immediately. Review SendinBlue audit logs for any unauthorized activities."
  },
  "SentryOrgToken": {
    "service": "Sentry",
    "category": "Error Tracking Service",
    "impact": "Unauthorized interaction with Sentry programmatically, allowing broad access to an entire organization's error tracking data, including project configurations, sensitive error details, and user information, leading to data exfiltration or disruption of monitoring.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Sentry Organization Auth Token.\n2. Attempt to list projects within the organization, retrieve detailed error events (which might contain sensitive data like stack traces, user info), or modify organization settings using `sentry-cli` or the Sentry API with the found token.\n3. Verify successful administrative access or data retrieval.",
    "remediation": "Immediately revoke the exposed Sentry Organization Auth Token through the Sentry organization settings. Generate a new token with the least privilege necessary for its intended use case and review Sentry audit logs for any unauthorized activities."
  },
  "SentryToken": {
    "service": "Sentry",
    "category": "Error Tracking Service",
    "impact": "Unauthorized access to and management of projects and organizations, potentially leading to exposure of sensitive error details, manipulation of monitoring settings, or disruption of error tracking for applications.",
    "severity": "High",
    "poc_template": "1. Locate exposed Sentry token.\n2. Attempt to list projects or retrieve error events using the Sentry API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Sentry token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "SerpStack": {
    "service": "SerpStack",
    "category": "Search Engine Results Scraper",
    "impact": "Unauthorized scraping of search engine results and access to search data, potentially leading to excessive API usage charges or data exfiltration for competitive intelligence or other purposes.",
    "severity": "Low",
    "poc_template": "1. Locate exposed SerpStack keys.\n2. Use the keys to scrape search engine results for a query via the SerpStack API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the SerpStack keys immediately."
  },
  "Serphouse": {
    "service": "Serphouse",
    "category": "Search Engine Result Page Data",
    "impact": "Unauthorized access to search engine result page data and performance of various operations on it, potentially leading to excessive API usage charges or data scraping for competitive intelligence.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Serphouse API key.\n2. Use the key to retrieve SERP data for a search query via the Serphouse API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Serphouse API key immediately."
  },
  "Sheety": {
    "service": "Sheety",
    "category": "Google Sheets as API",
    "impact": "Unauthorized access to and modification of data in linked Google Sheets, potentially leading to data manipulation, data exfiltration, or disruption of data-driven applications.",
    "severity": "High",
    "poc_template": "1. Locate exposed Sheety API keys.\n2. Attempt to read or modify data in a linked Google Sheet using the Sheety API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Sheety API keys immediately. Review the linked Google Sheet's access permissions."
  },
  "Sherpadesk": {
    "service": "Sherpadesk",
    "category": "Helpdesk & Service Desk Software",
    "impact": "Unauthorized access to and management of support tickets and other related data, potentially leading to data breaches, support ticket manipulation, or exposure of sensitive customer service details.",
    "severity": "High",
    "poc_template": "1. Locate exposed Sherpadesk keys.\n2. Attempt to list tickets or retrieve customer information using the Sherpadesk API with the found keys.\n3. Verify successful data access.",
    "remediation": "Rotate the Sherpadesk keys immediately."
  },
  "Shipday": {
    "service": "Shipday",
    "category": "Delivery Management Software",
    "impact": "Unauthorized access to and modification of delivery data, potentially leading to unauthorized delivery changes, access to driver/customer information, or disruption of logistics operations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Shipday API keys.\n2. Attempt to retrieve delivery tasks, modify order status, or access driver locations using the Shipday API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Shipday API keys immediately. Review all delivery logs for unauthorized activity."
  },
  "ShodanKey": {
    "service": "Shodan",
    "category": "IoT Search Engine",
    "impact": "Unauthorized querying of the Shodan database for information on Internet-connected devices, potentially leading to reconnaissance of vulnerable systems, data scraping, or misuse of security intelligence.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Shodan API key.\n2. Use the key to query the Shodan database for device information (e.g., open ports, vulnerabilities) via the Shodan API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Shodan API key immediately."
  },
  "Shopify": {
    "service": "Shopify",
    "category": "Ecommerce Platform",
    "impact": "Unauthorized access to customer data, orders, products, and other e-commerce functionalities, potentially leading to financial fraud, customer data theft, or disruption of online store operations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Shopify API keys.\n2. Attempt to list customers, create orders, or modify products using the Shopify API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Shopify API keys immediately. Review all store activity for unauthorized changes."
  },
  "Shortcut": {
    "service": "Shortcut",
    "category": "Project Management Tool",
    "impact": "Unauthorized access to and modification of project data, potentially leading to project disruption, data theft, or exposure of sensitive project details.",
    "severity": "High",
    "poc_template": "1. Locate exposed Shortcut API keys.\n2. Attempt to list stories, create tasks, or modify project details using the Shortcut API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Shortcut API keys immediately."
  },
  "Shotstack": {
    "service": "Shotstack",
    "category": "Video Editing API",
    "impact": "Unauthorized access to and utilization of video rendering and editing capabilities, potentially leading to excessive API usage charges, unauthorized video creation/manipulation, or exposure of sensitive video content.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Shotstack API keys.\n2. Attempt to render a video or retrieve asset information using the Shotstack API with the found keys.\n3. Verify successful video processing.",
    "remediation": "Rotate the Shotstack API keys immediately."
  },
  "Shutterstock": {
    "service": "Shutterstock",
    "category": "Stock Media Provider",
    "impact": "Unauthorized access to and modification of stock photography, footage, music, and editing tools, potentially leading to excessive API usage charges or misuse of copyrighted content.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Shutterstock API keys.\n2. Use the keys to search for images or download assets via the Shutterstock API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Shutterstock API keys immediately."
  },
  "ShutterstockOAuth": {
    "service": "Shutterstock",
    "category": "Stock Media Provider",
    "impact": "Unauthorized access to and modification of user photos on Shutterstock's platform, potentially leading to privacy breaches, content manipulation, or unauthorized use of licensed content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Shutterstock OAuth credentials (access token).\n2. Attempt to list user photos or access user account details using the Shutterstock API with the found token.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke the exposed Shutterstock OAuth token immediately through Shutterstock's security settings or by forcing a token refresh/re-authorization for the application."
  },
  "Signable": {
    "service": "Signable",
    "category": "Electronic Signature Service",
    "impact": "Unauthorized authentication and access to Signable's API services, potentially leading to unauthorized document signing, tampering with contracts, or exposure of sensitive e-signature data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Signable tokens.\n2. Attempt to send a document for signature or retrieve signature request details using the Signable API with the found tokens.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Signable tokens immediately and generate new ones."
  },
  "Signalwire": {
    "service": "SignalWire",
    "category": "Communications Platform as a Service (CPaaS)",
    "impact": "Unauthorized access to and management of communication services such as voice, messaging, and video, potentially leading to unauthorized calls/messages, eavesdropping, or significant financial cost due to service usage.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed SignalWire credentials (Project ID, API Token).\n2. Attempt to send a test message, make a call, or interact with other communication services using the SignalWire API with the found credentials.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the SignalWire credentials immediately. Review SignalWire call/message logs for unauthorized activity."
  },
  "Signaturit": {
    "service": "Signaturit",
    "category": "Electronic Signature Service",
    "impact": "Unauthorized access to and management of signature requests and related data, potentially leading to unauthorized document signing, tampering with contracts, or exposure of sensitive e-signature information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Signaturit API keys.\n2. Attempt to send a document for signature or retrieve signature request details using the Signaturit API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Signaturit API keys immediately."
  },
  "Signupgenius": {
    "service": "SignupGenius",
    "category": "Online Sign-up Tool",
    "impact": "Unauthorized access to and management of sign-up forms and related data, potentially leading to manipulation of event registrations, exposure of sensitive participant information, or disruption of event planning.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed SignupGenius API keys.\n2. Attempt to list sign-ups or modify event details using the SignupGenius API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the SignupGenius API keys immediately."
  },
  "Sigopt": {
    "service": "Sigopt",
    "category": "Machine Learning Optimization Platform",
    "impact": "Unauthorized access to and management of experiments on the Sigopt platform, potentially leading to manipulation of machine learning model optimization, exposure of sensitive research data, or resource abuse.",
    "severity": "High",
    "poc_template": "1. Locate exposed Sigopt API keys.\n2. Attempt to list experiments, create new experiments, or log experiment results using the Sigopt API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Sigopt API keys immediately."
  },
  "SimFin": {
    "service": "SimFin",
    "category": "Financial Data APIs",
    "impact": "Unauthorized access to financial data, potentially leading to excessive API usage charges or data scraping of sensitive financial information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed SimFin API keys.\n2. Use the keys to fetch financial data (e.g., company financials, stock prices) via the SimFin API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the SimFin API keys immediately."
  },
  "Simplesat": {
    "service": "Simplesat",
    "category": "Customer Satisfaction Survey Tool",
    "impact": "Unauthorized access to and management of customer feedback data, potentially leading to exposure of sensitive customer opinions, manipulation of survey results, or disruption of feedback collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Simplesat API keys.\n2. Attempt to retrieve survey results or manage feedback data using the Simplesat API with the found keys.\n3. Verify successful data access.",
    "remediation": "Rotate the Simplesat API keys immediately."
  },
  "SimplyNoted": {
    "service": "SimplyNoted",
    "category": "Personalized Handwritten Notes Service",
    "impact": "Unauthorized access to and sending of personalized handwritten notes, potentially leading to unauthorized communication, impersonation, or resource abuse.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed SimplyNoted API keys.\n2. Attempt to send a test handwritten note using the SimplyNoted API with the found keys.\n3. Verify successful note creation/sending.",
    "remediation": "Rotate the SimplyNoted API keys immediately."
  },
  "Simvoly": {
    "service": "Simvoly",
    "category": "Website & Online Store Builder",
    "impact": "Unauthorized access to and management of site data and functionalities, potentially leading to website defacement, content manipulation, or disruption of online store operations.",
    "severity": "High",
    "poc_template": "1. Locate exposed Simvoly API keys.\n2. Attempt to list sites, modify content, or access store data using the Simvoly API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Simvoly API keys immediately."
  },
  "SinchMessage": {
    "service": "Sinch",
    "category": "Cloud Communications Platform",
    "impact": "Unauthorized sending and receiving of messages, calls, and other communications, potentially leading to spamming, phishing attacks, or unauthorized access to communication data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Sinch API keys.\n2. Attempt to send a test message or make a call using the Sinch API with the found keys.\n3. Verify successful communication.",
    "remediation": "Revoke and regenerate the Sinch API keys immediately. Review Sinch logs for unauthorized activity."
  },
  "Sirv": {
    "service": "Sirv",
    "category": "Media Management (Image Optimization)",
    "impact": "Unauthorized access to and management of media files, including image optimization and delivery, potentially leading to content manipulation, unauthorized file deletion, or disruption of media presentation.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Sirv API keys.\n2. Attempt to upload images, process existing images, or manage assets using the Sirv API with the found keys.\n3. Verify successful media manipulation.",
    "remediation": "Rotate the Sirv API keys immediately."
  },
  "Siteleaf": {
    "service": "Siteleaf",
    "category": "Content Management System (CMS)",
    "impact": "Unauthorized access to and modification of site content and settings, potentially leading to unauthorized content publishing, website defacement, or disruption of content management workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Siteleaf API keys.\n2. Attempt to list sites, modify content, or update settings using the Siteleaf API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Siteleaf API keys immediately."
  },
  "Skrappio": {
    "service": "Skrapp.io",
    "category": "Email Verification & Enrichment",
    "impact": "Unauthorized access to and utilization of email verification and enrichment services, potentially leading to excessive API usage charges or the misuse of the service for lead generation or spam list validation.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Skrapp.io API keys.\n2. Use the keys to verify or enrich an email address via the Skrapp.io API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Skrapp.io API keys immediately."
  },
  "SkyBiometry": {
    "service": "SkyBiometry",
    "category": "Facial Recognition Service",
    "impact": "Unauthorized access to and utilization of facial recognition APIs, potentially leading to excessive API usage charges or the processing of sensitive facial data without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed SkyBiometry API keys.\n2. Use the keys to detect faces in an image or analyze facial attributes via the SkyBiometry API.\n3. Verify successful facial analysis.",
    "remediation": "Rotate the SkyBiometry API keys immediately."
  },
  "Slack": {
    "service": "Slack",
    "category": "Team Collaboration Platform",
    "impact": "Unauthorized authentication to Slack's API, allowing broad access to various workspace resources and functionalities, including sending messages, accessing private channels, managing users, or exfiltrating sensitive communication data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Slack token (e.g., Bot Token, User Token).\n2. Use the token to make an API request (e.g., list channels, send a message to a channel, retrieve user profiles) using the Slack API.\n3. Verify successful API interaction and potential data access/manipulation.",
    "remediation": "Immediately revoke the exposed Slack token through the Slack workspace's 'Manage apps' or 'API tokens' settings. Review audit logs for any unauthorized activities related to the token."
  },
  "SlackWebhook": {
    "service": "Slack",
    "category": "Team Collaboration Platform",
    "impact": "Unauthorized sending of messages from external sources into Slack channels, potentially leading to spamming, phishing attempts, or disruption of channel communication.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Slack webhook URL.\n2. Construct a simple JSON payload and send a POST request to the webhook URL.\n3. Verify that the message appears in the specified Slack channel.",
    "remediation": "Delete the exposed Slack webhook through the Slack workspace's 'Integrations' or 'Incoming Webhooks' settings immediately."
  },
  "Smartsheets": {
    "service": "Smartsheets",
    "category": "Work Management & Automation Platform",
    "impact": "Unauthorized access to and modification of data and automation workflows, potentially leading to data breaches, manipulation of project data, or disruption of business processes.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Smartsheets API keys.\n2. Attempt to list sheets, modify rows, or access automation workflows using the Smartsheets API with the found keys.\n3. Verify successful data manipulation and workflow access.",
    "remediation": "Revoke and regenerate the Smartsheets API keys immediately. Review Smartsheets audit logs for any unauthorized activities."
  },
  "SmartyStreets": {
    "service": "SmartyStreets",
    "category": "Address Validation Services",
    "impact": "Unauthorized access to address validation services, potentially leading to excessive API usage charges or misuse of the service for address data scraping or verification for malicious purposes.",
    "severity": "Low",
    "poc_template": "1. Locate exposed SmartyStreets API keys.\n2. Use the keys to validate an address via the SmartyStreets API.\n3. Verify successful validation result.",
    "remediation": "Rotate the SmartyStreets API keys immediately."
  },
  "Smooch": {
    "service": "Smooch (Sunshine Conversations)",
    "category": "Messaging Platform",
    "impact": "Unauthorized access to and management of customer communications across various messaging channels, potentially leading to unauthorized messaging, privacy breaches, or exposure of sensitive customer interactions.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Smooch API keys.\n2. Attempt to send a message to a customer or retrieve conversation history using the Smooch API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Smooch API keys immediately. Review all communication logs for unauthorized activity."
  },
  "Snipcart": {
    "service": "Snipcart",
    "category": "Shopping Cart Platform",
    "impact": "Unauthorized access to and management of e-commerce functionalities, including orders, products, and customers, potentially leading to financial fraud, customer data theft, or disruption of online store operations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Snipcart API keys.\n2. Attempt to list orders, modify products, or access customer data using the Snipcart API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Snipcart API keys immediately. Review all store activity for unauthorized changes."
  },
  "Snowflake": {
    "service": "Snowflake",
    "category": "Cloud Data Platform",
    "impact": "Unauthorized access to and manipulation of data stored in Snowflake, potentially leading to complete data compromise, data exfiltration, injection of malicious queries, or denial of service for data warehousing, data lakes, and data sharing capabilities.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Snowflake credentials (username, password, account identifier).\n2. Attempt to connect to the Snowflake instance using a SQL client (e.g., SnowSQL CLI, DBeaver) with the found credentials.\n3. Verify successful connection and attempt to query/modify sensitive tables and databases.",
    "remediation": "Immediately rotate Snowflake credentials. Implement strong access controls (RBAC), network policies, and multi-factor authentication. Review Snowflake query history and access logs for unauthorized activity."
  },
  "SnykKey": {
    "service": "Snyk",
    "category": "Developer Security Platform",
    "impact": "Unauthorized access to and management of Snyk services, potentially leading to scanning private repositories for vulnerabilities, accessing sensitive dependency data, or manipulating security policies.",
    "severity": "High",
    "poc_template": "1. Locate exposed Snyk API key.\n2. Configure Snyk CLI or use the Snyk API with the found key.\n3. Attempt to scan a project, list vulnerabilities, or access organization settings.\n4. Verify successful access and security data interaction.",
    "remediation": "Revoke the exposed Snyk API key and generate a new one immediately. Review Snyk audit logs for any unauthorized activities."
  },
  "SonarCloud": {
    "service": "SonarCloud",
    "category": "Code Quality & Security Service",
    "impact": "Unauthorized access to project analysis and quality reports, potentially leading to exposure of sensitive code vulnerabilities, manipulation of code quality metrics, or disruption of code analysis workflows.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed SonarCloud token.\n2. Attempt to retrieve project analysis results or access quality gate status using the SonarCloud API with the found token.\n3. Verify successful data access.",
    "remediation": "Rotate the SonarCloud token immediately."
  },
  "Sourcegraph": {
    "service": "Sourcegraph",
    "category": "Code Search & Navigation Engine",
    "impact": "Unauthorized access to and interaction with Sourcegraph APIs, potentially leading to access to private code repositories, exposure of internal code intelligence, or resource abuse.",
    "severity": "High",
    "poc_template": "1. Locate exposed Sourcegraph tokens.\n2. Attempt to search private code, access code insights, or configure Sourcegraph extensions using the Sourcegraph API with the found tokens.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Sourcegraph tokens immediately. Review Sourcegraph audit logs for any unauthorized activities."
  },
  "SourcegraphCody": {
    "service": "Sourcegraph Cody",
    "category": "Code Intelligence Tool",
    "impact": "Unauthorized access to Sourcegraph Cody services, potentially leading to unauthorized code suggestions, access to private code context, or misuse of AI-powered developer tools.",
    "severity": "High",
    "poc_template": "1. Locate exposed Sourcegraph Cody key.\n2. Attempt to use the key to interact with Cody's code intelligence features (e.g., generate code, answer questions about code) via its API.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Sourcegraph Cody key immediately."
  },
  "SpeechTextAI": {
    "service": "SpeechTextAI",
    "category": "Speech-to-Text Conversion",
    "impact": "Unauthorized access to and utilization of speech-to-text services, potentially leading to excessive API usage charges or the transcription of sensitive audio without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed SpeechTextAI API key.\n2. Use the key to submit an audio file for transcription via the SpeechTextAI API.\n3. Verify successful transcription.",
    "remediation": "Rotate the SpeechTextAI API key immediately."
  },
  "SplunkOberservabilityToken": {
    "service": "Splunk Observability",
    "category": "Monitoring & Analytics",
    "impact": "Unauthorized access to and interaction with Splunk's observability suite, allowing for monitoring and analyzing application performance and infrastructure, potentially leading to exposure of sensitive operational data, logs, and metrics, or injection of false telemetry.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Splunk Observability Token.\n2. Attempt to send metrics, logs, or traces to Splunk or query existing data using Splunk APIs with the found token.\n3. Verify successful data ingestion or retrieval.",
    "remediation": "Immediately revoke the exposed Splunk Observability Token and generate a new one with minimal necessary permissions. Review Splunk audit logs for any unauthorized activities."
  },
  "Spoonacular": {
    "service": "Spoonacular",
    "category": "Food & Recipe API",
    "impact": "Unauthorized access to and management of food and recipe data, potentially leading to excessive API usage charges or data scraping of culinary information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Spoonacular API keys.\n2. Use the keys to search for recipes or retrieve food nutrition data via the Spoonacular API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Spoonacular API keys immediately."
  },
  "Sportsmonk": {
    "service": "Sportsmonk",
    "category": "Sports Data Provider",
    "impact": "Unauthorized access to various API endpoints for sports data, potentially leading to excessive API usage charges or data scraping of sports statistics and live data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Sportsmonk API keys.\n2. Use the keys to query sports data (e.g., live scores, team statistics) via the Sportsmonk API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Sportsmonk API keys immediately."
  },
  "Square": {
    "service": "Square",
    "category": "Financial Services & Mobile Payment",
    "impact": "Unauthorized access to and management of payments, transactions, and other financial data, potentially leading to financial fraud, unauthorized payment processing, or exposure of sensitive customer billing information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Square API keys.\n2. Attempt to retrieve transaction details, create a payment, or manage customer profiles using the Square API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Square API keys immediately. Review all transaction logs for unauthorized activity."
  },
  "SquareApp": {
    "service": "Square",
    "category": "Financial Services & Mobile Payment",
    "impact": "Unauthorized access to and management of payment processing and other financial services, potentially leading to financial fraud, unauthorized payment initiation, or exposure of sensitive payment information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Square credentials.\n2. Attempt to process a test payment, retrieve sales data, or manage items using the Square API with the found credentials.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Square credentials immediately. Review all transaction logs for unauthorized activity."
  },
  "Squarespace": {
    "service": "Squarespace",
    "category": "Website Building & Hosting",
    "impact": "Unauthorized management and modification of website content and configuration, potentially leading to website defacement, content manipulation, or disruption of online presence.",
    "severity": "High",
    "poc_template": "1. Locate exposed Squarespace API keys.\n2. Attempt to list pages, modify content, or update site settings using the Squarespace API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Squarespace API keys immediately."
  },
  "Squareup": {
    "service": "Squareup",
    "category": "Financial Services & Mobile Payment",
    "impact": "Unauthorized interaction with Squareup's APIs for processing payments and accessing customer data, potentially leading to financial fraud, unauthorized payment processing, or exposure of sensitive customer billing information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Squareup key.\n2. Attempt to retrieve transaction details, process a test payment, or access customer profiles using the Squareup API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Squareup key immediately and generate a new one. Review all transaction logs for unauthorized activity."
  },
  "SslMate": {
    "service": "SslMate",
    "category": "SSL Certificate Management",
    "impact": "Unauthorized management and automation of SSL certificates, potentially leading to unauthorized certificate issuance, revocation of legitimate certificates, or security bypasses for encrypted communications.",
    "severity": "High",
    "poc_template": "1. Locate exposed SslMate API keys.\n2. Attempt to list certificates, order a new certificate, or revoke an existing certificate using the SslMate API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the SslMate API keys immediately."
  },
  "Statuscake": {
    "service": "Statuscake",
    "category": "Website Monitoring Service",
    "impact": "Unauthorized access to and management of website monitoring configurations and data, potentially leading to disabling alerts, altering uptime checks, or exposing sensitive website performance data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Statuscake API keys.\n2. Attempt to list uptime tests or modify monitoring settings using the Statuscake API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Statuscake API keys immediately."
  },
  "Statuspage": {
    "service": "Statuspage",
    "category": "Incident Communication Tool",
    "impact": "Unauthorized management and updating of status pages, potentially leading to publishing false incident information, creating unauthorized incidents, or disrupting critical communication during outages.",
    "severity": "High",
    "poc_template": "1. Locate exposed Statuspage API keys.\n2. Attempt to create a new incident, update a component status, or post an announcement using the Statuspage API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Statuspage API keys immediately. Review all status page activity for unauthorized changes."
  },
  "Statuspal": {
    "service": "Statuspal",
    "category": "Status Page Service",
    "impact": "Unauthorized management of status pages and subscriptions, potentially leading to publishing false incident information, creating unauthorized incidents, or disrupting critical communication during outages.",
    "severity": "High",
    "poc_template": "1. Locate exposed Statuspal API keys.\n2. Attempt to list status pages, create an incident, or update components using the Statuspal API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Statuspal API keys immediately. Review all status page activity for unauthorized changes."
  },
  "Stitchdata": {
    "service": "Stitchdata",
    "category": "Cloud ETL Service",
    "impact": "Unauthorized management and automation of data pipelines, potentially leading to data exfiltration from various sources, data manipulation during transfer, or disruption of data warehousing processes.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Stitchdata API keys.\n2. Attempt to list integrations, start data replication jobs, or access data sources using the Stitchdata API with the found keys.\n3. Verify successful API interaction and data access.",
    "remediation": "Revoke and regenerate the Stitchdata API keys immediately. Review Stitchdata audit logs for any unauthorized activities."
  },
  "Stockdata": {
    "service": "Stockdata",
    "category": "Stock Market Data",
    "impact": "Unauthorized access to and retrieval of stock market information, potentially leading to excessive API usage charges or data scraping of sensitive financial data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Stockdata API keys.\n2. Use the keys to fetch stock prices or historical data via the Stockdata API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Stockdata API keys immediately."
  },
  "Storecove": {
    "service": "Storecove",
    "category": "Electronic Invoicing API",
    "impact": "Unauthorized access to and management of electronic invoicing data, potentially leading to financial fraud, unauthorized invoice creation/modification, or exposure of sensitive billing information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Storecove API keys.\n2. Attempt to create an e-invoice, retrieve invoice details, or list transactions using the Storecove API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Storecove API keys immediately. Review all invoicing logs for unauthorized activity."
  },
  "Stormboard": {
    "service": "Stormboard",
    "category": "Digital Workspace (Brainstorming)",
    "impact": "Unauthorized access to and modification of data within the collaborative workspace, potentially leading to intellectual property theft, content tampering, or disruption of brainstorming sessions.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Stormboard API keys.\n2. Attempt to list stormboards, add ideas, or modify content using the Stormboard API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Stormboard API keys immediately."
  },
  "Stormglass": {
    "service": "Stormglass",
    "category": "Weather Data Provider",
    "impact": "Unauthorized access to weather data services, potentially leading to excessive API usage charges or data scraping of meteorological information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Stormglass API keys.\n2. Use the keys to fetch weather data for a location via the Stormglass API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Stormglass API keys immediately."
  },
  "StoryblokAccessToken": {
    "service": "Storyblok",
    "category": "Headless CMS",
    "impact": "Unauthorized access to and modification of content within a Storyblok space, potentially leading to unauthorized content publishing, content tampering, or deletion of crucial digital content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Storyblok Access Token.\n2. Attempt to retrieve or modify content entries via the Storyblok API with the found token.\n3. Verify successful content manipulation.",
    "remediation": "Revoke the Storyblok Access Token immediately and generate a new one, storing it securely."
  },
  "StoryblokPersonalAccessToken": {
    "service": "Storyblok",
    "category": "Headless CMS",
    "impact": "Unauthorized access to and modification of content using the Management APIs, potentially leading to unauthorized content publishing, content tampering, or deletion of crucial digital content within a Storyblok space.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Storyblok Personal Access Token.\n2. Use the token with the Storyblok Management API to create, edit, update, or delete content entries.\n3. Verify successful administrative manipulation of content.",
    "remediation": "Immediately revoke the exposed Storyblok Personal Access Token through Storyblok's settings. Generate a new token with minimal necessary permissions and a short lifespan, storing it securely."
  },
  "Storychief": {
    "service": "Storychief",
    "category": "Content Marketing Platform",
    "impact": "Unauthorized access to and management of content and integrations, potentially leading to unauthorized content publishing, data manipulation across integrated platforms, or exposure of sensitive content marketing strategies.",
    "severity": "High",
    "poc_template": "1. Locate exposed Storychief API keys.\n2. Attempt to list stories, publish content, or manage integrations using the Storychief API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Storychief API keys immediately."
  },
  "Strava": {
    "service": "Strava",
    "category": "Workout App",
    "impact": "Unauthorized access to user workout data, including activity details, routes, and personal performance metrics, potentially leading to privacy breaches or misuse of fitness information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Strava OAuth API keys.\n2. Attempt to retrieve user activities or profile data using the Strava API with the found OAuth token.\n3. Verify successful data access.",
    "remediation": "Invalidate the exposed Strava OAuth API keys immediately and advise users to revoke access for the compromised application."
  },
  "Streak": {
    "service": "Streak",
    "category": "CRM Software (Gmail Integration)",
    "impact": "Unauthorized access to and management of CRM data within Streak, potentially leading to data breaches, lead manipulation, or exposure of sensitive customer interactions within Gmail.",
    "severity": "High",
    "poc_template": "1. Locate exposed Streak API keys.\n2. Attempt to list pipelines, create boxes (leads), or access email conversations linked to CRM data using the Streak API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Streak API keys immediately."
  },
  "Stripe": {
    "service": "Stripe",
    "category": "Payment Processing Platform",
    "impact": "Unauthorized interaction with Stripe's services for processing payments, managing subscriptions, and more, potentially leading to financial fraud, unauthorized transactions, or exposure of sensitive customer billing information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Stripe API keys (publishable and secret keys).\n2. Attempt to create a charge, manage a subscription, or retrieve customer details using the Stripe API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke and regenerate the Stripe API keys. Review all transaction and customer data logs for unauthorized activity."
  },
  "StripePaymentIntent": {
    "service": "Stripe",
    "category": "Payment Processing Platform",
    "impact": "Unauthorized initiation and management of payment flows, including confirmation, authentication, and capture of funds, potentially leading to financial fraud or unauthorized transactions.",
    "severity": "High",
    "poc_template": "1. Locate exposed Stripe Payment Intent (client secret).\n2. Attempt to confirm or capture a payment for the associated Payment Intent using the Stripe API with the found secret.\n3. Verify successful payment manipulation.",
    "remediation": "Invalidate the exposed Stripe Payment Intent client secret immediately. This is typically short-lived, but ensure it's not reused or exposed in logs."
  },
  "Stripo": {
    "service": "Stripo",
    "category": "Email Template Builder",
    "impact": "Unauthorized access to and modification of email templates, potentially leading to unauthorized template changes, injection of malicious code into templates, or disruption of email design workflows.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Stripo API keys.\n2. Attempt to list templates or modify an email template using the Stripo API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Stripo API keys immediately."
  },
  "Stytch": {
    "service": "Stytch",
    "category": "Passwordless Authentication Platform",
    "impact": "Unauthorized access to and management of authentication services, potentially leading to unauthorized user creation, account takeover, or bypassing of authentication mechanisms.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Stytch API keys.\n2. Attempt to authenticate a user, create a new user, or manage authentication methods using the Stytch API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Stytch API keys immediately. Review Stytch audit logs for any unauthorized activities."
  },
  "Sugester": {
    "service": "Sugester",
    "category": "Customer Support Software",
    "impact": "Unauthorized access to and management of data within the Sugester platform, potentially leading to data breaches, manipulation of customer interactions, or disruption of support operations.",
    "severity": "High",
    "poc_template": "1. Locate exposed Sugester API keys.\n2. Attempt to list tickets or retrieve customer interactions using the Sugester API with the found keys.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Sugester API keys immediately."
  },
  "SumoLogicKey": {
    "service": "Sumo Logic",
    "category": "Cloud-based Machine Data Analytics",
    "impact": "Unauthorized access to and management of data within the Sumo Logic platform, including log data and analytics, potentially leading to data exfiltration of sensitive logs, injection of false data, or disruption of monitoring and security analysis.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Sumo Logic keys.\n2. Attempt to send new log data, query existing logs, or access dashboards using the Sumo Logic API with the found keys.\n3. Verify successful data ingestion or retrieval.",
    "remediation": "Revoke the exposed Sumo Logic keys and generate new ones immediately. Review Sumo Logic audit logs for any unauthorized activities."
  },
  "SupabaseToken": {
    "service": "Supabase",
    "category": "Open Source Firebase Alternative",
    "impact": "Unauthorized access to and management of Supabase projects and data, potentially leading to data breaches, database manipulation, or unauthorized access to APIs and authentication services.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Supabase token.\n2. Configure Supabase CLI or use Supabase client libraries with the found token.\n3. Attempt to query database tables, manage authentication, or access storage buckets.\n4. Verify successful data manipulation and project control.",
    "remediation": "Revoke the exposed Supabase token immediately through your Supabase project settings. Generate a new token with minimal necessary permissions and ensure it's securely stored."
  },
  "SuperNotesAPI": {
    "service": "SuperNotes",
    "category": "Note-taking Application",
    "impact": "Unauthorized access to and management of user notes and other data within the application, potentially leading to data theft, note manipulation, or exposure of sensitive personal information.",
    "severity": "High",
    "poc_template": "1. Locate exposed SuperNotes API key.\n2. Attempt to list user notes, create new notes, or modify existing notes using the SuperNotes API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the SuperNotes API key immediately."
  },
  "SurveyAnyplace": {
    "service": "SurveyAnyplace",
    "category": "Survey & Quiz Platform",
    "impact": "Unauthorized access to and management of surveys and quizzes, potentially leading to manipulation of survey questions, exposure of sensitive responses, or disruption of data collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed SurveyAnyplace credential.\n2. Attempt to list surveys or retrieve responses using the SurveyAnyplace API with the found credential.\n3. Verify successful data access.",
    "remediation": "Revoke the exposed SurveyAnyplace credential and generate a new one immediately."
  },
  "SurveyBot": {
    "service": "SurveyBot",
    "category": "Survey Conducting Service",
    "impact": "Unauthorized access to and management of surveys, potentially leading to manipulation of survey questions, exposure of sensitive responses, or disruption of data collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed SurveyBot API keys.\n2. Attempt to create a new survey, manage existing surveys, or retrieve survey responses using the SurveyBot API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Rotate the SurveyBot API keys immediately."
  },
  "SurveySparrow": {
    "service": "SurveySparrow",
    "category": "Survey Platform",
    "impact": "Unauthorized access to and management of surveys and responses, potentially leading to exposure of sensitive feedback, manipulation of survey results, or disruption of data collection.",
    "severity": "High",
    "poc_template": "1. Locate exposed SurveySparrow key.\n2. Attempt to list surveys or retrieve responses using the SurveySparrow API with the found key.\n3. Verify successful data access.",
    "remediation": "Revoke the exposed SurveySparrow key and generate a new one immediately."
  },
  "Survicate": {
    "service": "Survicate",
    "category": "Survey Platform",
    "impact": "Unauthorized access to and management of surveys and responses, potentially leading to exposure of sensitive customer feedback, manipulation of survey results, or disruption of data collection.",
    "severity": "High",
    "poc_template": "1. Locate exposed Survicate API keys.\n2. Attempt to list surveys or retrieve responses using the Survicate API with the found keys.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Survicate API keys immediately."
  },
  "Swell": {
    "service": "Swell",
    "category": "eCommerce Platform",
    "impact": "Unauthorized access to and modification of online store data, including products, orders, and customer information, potentially leading to financial fraud, customer data theft, or disruption of e-commerce operations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Swell API keys.\n2. Attempt to list products, create orders, or access customer data using the Swell API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Swell API keys immediately. Review all store activity for unauthorized changes."
  },
  "Swiftype": {
    "service": "Swiftype",
    "category": "Search Technology",
    "impact": "Unauthorized access to and manipulation of search data, potentially leading to exposure of search query insights, manipulation of search results, or disruption of search functionalities for websites and applications.",
    "severity": "High",
    "poc_template": "1. Locate exposed Swiftype keys.\n2. Attempt to index documents, query search results, or manage search engines using the Swiftype API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Swiftype keys immediately."
  }
}





























{
  "Tailscale": {
    "service": "Tailscale",
    "category": "VPN & Secure Networking",
    "impact": "Unauthorized authentication and interaction with the Tailscale API, potentially leading to unauthorized device enrollment, network configuration changes, or access to sensitive network topology information, compromising network security.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Tailscale API key.\n2. Attempt to list devices, add new devices to the network, or manage network policies using the Tailscale API with the found key.\n3. Verify successful API interaction and control over the network.",
    "remediation": "Revoke the exposed Tailscale API key immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Tallyfy": {
    "service": "Tallyfy",
    "category": "Process & Workflow Automation",
    "impact": "Unauthorized access to and automation of workflows and processes, potentially leading to disruption of business operations, data manipulation, or exposure of sensitive process configurations.",
    "severity": "High",
    "poc_template": "1. Locate exposed Tallyfy API key.\n2. Attempt to list processes, start a new workflow, or modify existing tasks using the Tallyfy API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Tallyfy API key immediately."
  },
  "TatumIO": {
    "service": "Tatum",
    "category": "Blockchain Infrastructure",
    "impact": "Unauthorized access to and interaction with blockchain services, potentially leading to resource abuse, unauthorized transaction submissions, or access to sensitive blockchain data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Tatum API key.\n2. Attempt to perform a blockchain operation (e.g., retrieve transaction details, mint an NFT, send a cryptocurrency) using the Tatum API with the found key.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Tatum API key immediately. Review all blockchain activity for unauthorized transactions."
  },
  "Taxjar": {
    "service": "Taxjar",
    "category": "Sales Tax Automation",
    "impact": "Unauthorized access to and management of sales tax calculations, reporting, and filings, potentially leading to financial discrepancies, inaccurate tax reporting, or exposure of sensitive sales data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Taxjar API keys.\n2. Attempt to calculate sales tax for an order, retrieve transaction data, or access tax reports using the Taxjar API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Taxjar API keys immediately. Review all tax-related logs for unauthorized activity."
  },
  "Teamgate": {
    "service": "Teamgate",
    "category": "Sales CRM Platform",
    "impact": "Unauthorized access to and management of sales data and CRM functionalities, potentially leading to data breaches, lead manipulation, or exposure of sensitive sales information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Teamgate tokens and keys.\n2. Attempt to list or modify sales leads, deals, or contacts using the Teamgate API with the found credentials.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Teamgate tokens and keys immediately."
  },
  "TeamworkCRM": {
    "service": "TeamworkCRM",
    "category": "Customer Relationship Management (CRM)",
    "impact": "Unauthorized access to and management of sales pipeline and customer interactions, potentially leading to data breaches, lead manipulation, or exposure of sensitive customer data.",
    "severity": "High",
    "poc_template": "1. Locate exposed TeamworkCRM tokens.\n2. Attempt to list or modify deals, companies, or contacts using the TeamworkCRM API with the found tokens.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the TeamworkCRM tokens immediately."
  },
  "TeamworkDesk": {
    "service": "TeamworkDesk",
    "category": "Helpdesk Software",
    "impact": "Unauthorized access to and management of customer support tickets and other related data, potentially leading to data breaches, support ticket manipulation, or exposure of sensitive customer communications.",
    "severity": "High",
    "poc_template": "1. Locate exposed TeamworkDesk tokens.\n2. Attempt to list tickets, create new tickets, or retrieve customer details using the TeamworkDesk API with the found tokens.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke and regenerate the TeamworkDesk tokens immediately."
  },
  "TeamworkSpaces": {
    "service": "TeamworkSpaces",
    "category": "Collaboration Tool",
    "impact": "Unauthorized access to and modification of spaces and documents, potentially leading to intellectual property theft, content tampering, or exposure of sensitive collaborative information.",
    "severity": "High",
    "poc_template": "1. Locate exposed TeamworkSpaces key.\n2. Attempt to list spaces, modify documents, or access content within TeamworkSpaces using the API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the exposed TeamworkSpaces key and generate a new one immediately."
  },
  "TechnicalAnalysisApi": {
    "service": "TechnicalAnalysisApi",
    "category": "Financial Market Analysis",
    "impact": "Unauthorized access to and retrieval of technical analysis data for financial markets, potentially leading to excessive API usage charges or data scraping for trading strategies.",
    "severity": "Low",
    "poc_template": "1. Locate exposed TechnicalAnalysisApi key.\n2. Use the key to retrieve technical indicator data for a financial instrument via the TechnicalAnalysisApi.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the TechnicalAnalysisApi key immediately."
  },
  "Tefter": {
    "service": "Tefter",
    "category": "Bookmarking Service",
    "impact": "Unauthorized access to and management of bookmarks, potentially leading to exposure of private saved content or manipulation of user collections.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Tefter API keys.\n2. Attempt to list or modify bookmarks using the Tefter API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Tefter API keys immediately."
  },
  "TelegramBotToken": {
    "service": "Telegram Bot API",
    "category": "Messaging Platform (Bots)",
    "impact": "Unauthorized control over a Telegram bot, allowing for sending messages, managing chats, receiving updates, or potentially accessing user data depending on bot permissions. This could lead to spam, phishing, or unauthorized communication.",
    "severity": "High",
    "poc_template": "1. Locate exposed Telegram Bot API token.\n2. Use the token to send a test message to a chat, get bot info, or list recent updates using the Telegram Bot API.\n3. Verify successful bot control.",
    "remediation": "Immediately revoke the exposed Telegram Bot API token through BotFather on Telegram and generate a new one."
  },
  "Teletype": {
    "service": "Teletype",
    "category": "Messaging Service",
    "impact": "Unauthorized access to and sending of messages, potentially leading to unauthorized communication or resource abuse.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Teletype API keys.\n2. Attempt to send a test message using the Teletype API with the found keys.\n3. Verify successful message delivery.",
    "remediation": "Rotate the Teletype API keys immediately."
  },
  "Telnyx": {
    "service": "Telnyx",
    "category": "Communications Platform",
    "impact": "Unauthorized access to and management of voice, messaging, and other communication services, potentially leading to unauthorized calls/messages, eavesdropping, or significant financial cost due to service usage.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Telnyx keys.\n2. Attempt to send a test message, make a call, or manage communication resources using the Telnyx API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Telnyx keys immediately. Review Telnyx logs for unauthorized activities."
  },
  "TerraformCloudPersonalToken": {
    "service": "Terraform Cloud",
    "category": "Infrastructure Automation",
    "impact": "Unauthorized access to and management of infrastructure as code, potentially leading to unauthorized resource creation/deletion, privilege escalation, data breaches, or full environment compromise within the cloud infrastructure.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Terraform Cloud personal token.\n2. Configure Terraform CLI with the found token.\n3. Attempt to list workspaces, apply a plan, or destroy resources.\n4. Verify successful administrative control over infrastructure.",
    "remediation": "Immediately revoke the exposed Terraform Cloud personal token through Terraform Cloud settings. Generate a new token with minimal necessary permissions and a short lifespan, storing it securely."
  },
  "TestingBot": {
    "service": "TestingBot",
    "category": "Cross-Browser Testing",
    "impact": "Unauthorized automation of tests on various browsers and devices, potentially leading to resource abuse, exposure of sensitive test data, or unauthorized access to internal websites if tested.",
    "severity": "High",
    "poc_template": "1. Locate exposed TestingBot credentials.\n2. Attempt to launch a test session on a browser/device or retrieve test results using the TestingBot API with the found credentials.\n3. Verify successful test execution.",
    "remediation": "Revoke and regenerate TestingBot credentials immediately."
  },
  "Textmagic": {
    "service": "Textmagic",
    "category": "SMS Service",
    "impact": "Unauthorized sending and receiving of text messages, potentially leading to spamming, phishing attempts, or significant financial cost due to message charges.",
    "severity": "High",
    "poc_template": "1. Locate exposed Textmagic API keys.\n2. Attempt to send a test SMS message or check account balance using the Textmagic API with the found keys.\n3. Verify successful message delivery.",
    "remediation": "Revoke and regenerate the Textmagic API keys immediately."
  },
  "TheOddsApi": {
    "service": "TheOddsApi",
    "category": "Sports Data & Odds",
    "impact": "Unauthorized access to sports data and odds, potentially leading to excessive API usage charges or data scraping for betting or analytical purposes.",
    "severity": "Low",
    "poc_template": "1. Locate exposed TheOddsApi keys.\n2. Use the keys to fetch sports odds for a match via TheOddsApi.\n3. Verify successful data retrieval.",
    "remediation": "Rotate TheOddsApi keys immediately."
  },
  "Thinkific": {
    "service": "Thinkific",
    "category": "Online Course Platform",
    "impact": "Unauthorized access to and management of course data and user information, potentially leading to unauthorized course creation/modification, access to student data, or disruption of educational services.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Thinkific API keys.\n2. Attempt to list courses, enroll users, or access student details using the Thinkific API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Thinkific API keys immediately. Review Thinkific audit logs for unauthorized activities."
  },
  "ThousandEyes": {
    "service": "ThousandEyes",
    "category": "Network Intelligence & Monitoring",
    "impact": "Unauthorized access to and management of network performance data and monitoring services, potentially leading to exposure of sensitive network configurations, disruption of monitoring, or injection of false network performance data.",
    "severity": "High",
    "poc_template": "1. Locate exposed ThousandEyes API keys.\n2. Attempt to list tests, retrieve network data, or modify monitoring settings using the ThousandEyes API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the ThousandEyes API keys immediately."
  },
  "TicketMaster": {
    "service": "TicketMaster",
    "category": "Event Management & Ticketing",
    "impact": "Unauthorized access to and modification of event data and other related services, potentially leading to event manipulation, ticketing fraud, or exposure of sensitive event information.",
    "severity": "High",
    "poc_template": "1. Locate exposed TicketMaster API keys.\n2. Attempt to search for events, retrieve ticket details, or modify event information using the TicketMaster API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the TicketMaster API keys immediately."
  },
  "Tickettailor": {
    "service": "Tickettailor",
    "category": "Online Ticketing Platform",
    "impact": "Unauthorized management of events, orders, and tickets, potentially leading to event manipulation, ticketing fraud, or exposure of sensitive attendee and financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Tickettailor API keys.\n2. Attempt to list events, create orders, or access ticket details using the Tickettailor API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Tickettailor API keys immediately. Review all event and order logs for unauthorized activity."
  },
  "Tiingo": {
    "service": "Tiingo",
    "category": "Financial Data Platform",
    "impact": "Unauthorized access to various financial data and APIs, potentially leading to excessive API usage charges or data scraping of sensitive financial information for trading strategies.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Tiingo API keys.\n2. Use the keys to fetch stock data, cryptocurrency prices, or news via the Tiingo API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Tiingo API keys immediately."
  },
  "TimeCamp": {
    "service": "TimeCamp",
    "category": "Time Tracking Software",
    "impact": "Unauthorized access to and modification of time tracking data, potentially leading to inaccurate billing, financial fraud, or exposure of sensitive project and client time details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed TimeCamp API keys.\n2. Attempt to retrieve or modify time entries using the TimeCamp API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the TimeCamp API keys immediately."
  },
  "Timezoneapi": {
    "service": "Timezoneapi",
    "category": "Time Zone Information Service",
    "impact": "Unauthorized access to time zone information, potentially leading to excessive API usage charges or data scraping of geographical time data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Timezoneapi keys.\n2. Use the keys to retrieve time zone information for a location via the Timezoneapi.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Timezoneapi keys immediately."
  },
  "TinesWebhook": {
    "service": "Tines",
    "category": "Automation Platform",
    "impact": "Unauthorized triggering and interaction with Tines workflows, potentially leading to unauthorized execution of automated security or operational processes, data injection into workflows, or disruption of automation.",
    "severity": "High",
    "poc_template": "1. Locate exposed Tines Webhook URL.\n2. Send a test payload to the webhook URL using a POST request.\n3. Verify that the Tines workflow is triggered and performs the expected actions.",
    "remediation": "Delete or regenerate the Tines Webhook URL immediately. Implement strong validation within Tines workflows to prevent malicious inputs."
  },
  "Tmetric": {
    "service": "Tmetric",
    "category": "Time Tracking Service",
    "impact": "Unauthorized access to and management of time tracking data, potentially leading to inaccurate billing, financial fraud, or exposure of sensitive project and client time details.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Tmetric API keys.\n2. Attempt to retrieve or modify time entries using the Tmetric API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Rotate the Tmetric API keys immediately."
  },
  "Todoist": {
    "service": "Todoist",
    "category": "Task Management Application",
    "impact": "Unauthorized access to and management of tasks and projects within a user's account, potentially leading to task manipulation, exposure of sensitive personal information, or disruption of productivity.",
    "severity": "High",
    "poc_template": "1. Locate exposed Todoist API keys.\n2. Attempt to list tasks, add new tasks, or modify projects using the Todoist API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Todoist API keys immediately through Todoist's integration settings."
  },
  "Tokeet": {
    "service": "Tokeet",
    "category": "Property Management Software",
    "impact": "Unauthorized access to and modification of property data and management of bookings, potentially leading to property manipulation, unauthorized bookings, or exposure of sensitive guest information and financial details.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Tokeet API keys.\n2. Attempt to list properties, create a booking, or modify guest data using the Tokeet API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Tokeet API keys immediately. Review all booking logs for unauthorized activity."
  },
  "TomorrowIO": {
    "service": "Tomorrow.io",
    "category": "Weather Intelligence Platform",
    "impact": "Unauthorized access to weather data and insights, potentially leading to excessive API usage charges or data scraping of meteorological information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Tomorrow.io API keys.\n2. Use the keys to fetch weather data or forecasts via the Tomorrow.io API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Tomorrow.io API keys immediately."
  },
  "Tomtom": {
    "service": "TomTom",
    "category": "Mapping & Location Technologies",
    "impact": "Unauthorized access to and manipulation of mapping data and services, potentially leading to excessive API usage charges or data scraping of geographic information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed TomTom API keys.\n2. Use the keys to perform geocoding, route calculation, or map display via the TomTom API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the TomTom API keys immediately."
  },
  "Tradier": {
    "service": "Tradier",
    "category": "Financial Services (Trading)",
    "impact": "Unauthorized access to and management of trading accounts and execution of trades, potentially leading to financial fraud, unauthorized stock trades, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Tradier API keys.\n2. Attempt to retrieve account balance, place an order, or access trade history using the Tradier API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Tradier API keys immediately. Implement strong security measures like IP whitelisting for trading APIs."
  },
  "Transferwise": {
    "service": "TransferWise (Wise)",
    "category": "International Money Transfer Service",
    "impact": "Unauthorized access to and management of money transfers, potentially leading to financial fraud, unauthorized fund transfers, or exposure of sensitive financial data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed TransferWise API keys.\n2. Attempt to retrieve balance, create a transfer, or access recipient details using the TransferWise API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the TransferWise API keys immediately. Review all transfer logs for unauthorized activity."
  },
  "TravelPayouts": {
    "service": "TravelPayouts",
    "category": "Travel Affiliate Network",
    "impact": "Unauthorized interaction with various travel-related APIs, potentially leading to data scraping of travel data, unauthorized bookings for commissions, or resource abuse.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed TravelPayouts keys.\n2. Use the keys to search for flights/hotels or access travel offers via the TravelPayouts API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the TravelPayouts keys immediately."
  },
  "TravisCI": {
    "service": "Travis CI",
    "category": "Continuous Integration Service",
    "impact": "Unauthorized interaction with the Travis CI API, potentially leading to unauthorized build triggers, access to build logs, or manipulation of CI/CD pipelines, affecting software development workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Travis CI token.\n2. Attempt to list repositories, trigger a build, or access build history using the Travis CI API with the found token.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Travis CI token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "TrelloApiKey": {
    "service": "Trello",
    "category": "Collaboration Tool",
    "impact": "Unauthorized access to and modification of data within Trello boards, lists, and cards, potentially leading to project disruption, data theft, or exposure of sensitive task and project information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Trello API key (and potentially a user token).\n2. Attempt to list boards, create cards, or modify existing data using the Trello API with the found key.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the exposed Trello API key and any associated user tokens immediately."
  },
  "TrufflehogEnterprise": {
    "service": "TruffleHog Enterprise",
    "category": "Secret Detection & Verification",
    "impact": "Unauthorized access to and interaction with TruffleHog Enterprise services, potentially leading to exposure of sensitive security findings, bypassing secret detection, or manipulating scan configurations.",
    "severity": "High",
    "poc_template": "1. Locate exposed TruffleHog Enterprise keys/secrets.\n2. Attempt to run a scan, retrieve scan results, or configure repositories within TruffleHog Enterprise using the found credentials.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed TruffleHog Enterprise keys/secrets and generate new ones immediately. Review audit logs for unauthorized activities."
  },
  "TwelveData": {
    "service": "TwelveData",
    "category": "Financial Data APIs",
    "impact": "Unauthorized access to financial data for stock, forex, cryptocurrency, and more, potentially leading to excessive API usage charges or data scraping of sensitive financial information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed TwelveData API keys.\n2. Use the keys to fetch real-time or historical financial data via the TwelveData API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the TwelveData API keys immediately."
  },
  "Twilio": {
    "service": "Twilio",
    "category": "Cloud Communications Platform",
    "impact": "Unauthorized programmatic control over phone calls, text messages, and other communication functions, potentially leading to unauthorized calls/messages, eavesdropping, or significant financial cost due to service usage.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Twilio credentials (Account SID and Auth Token).\n2. Attempt to send a test SMS message or initiate a phone call using the Twilio API with the found credentials.\n3. Verify successful API interaction.",
    "remediation": "Immediately rotate the Twilio Auth Token through the Twilio Console. Review all call/message logs for unauthorized activity."
  },
  "TwilioApiKey": {
    "service": "Twilio",
    "category": "Cloud Communications Platform",
    "impact": "Unauthorized programmatic control over phone calls, text messages, and other communication functions, potentially leading to unauthorized calls/messages, eavesdropping, or significant financial cost due to service usage.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Twilio API key (different from Auth Token).\n2. Attempt to send a test SMS message or initiate a phone call using the Twilio API with the found API key and Account SID.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke the exposed Twilio API key through the Twilio Console. Review all call/message logs for unauthorized activity."
  },
  "Twist": {
    "service": "Twist",
    "category": "Team Communication App",
    "impact": "Unauthorized access to and management of Twist accounts and data, potentially leading to unauthorized message sending, eavesdropping on team conversations, or exposure of sensitive communication content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Twist access tokens.\n2. Attempt to list channels, send messages, or access user data using the Twist API with the found tokens.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Twist access tokens immediately and generate new ones."
  },
  "Twitch": {
    "service": "Twitch",
    "category": "Live Streaming Service",
    "impact": "Unauthorized access to and modification of data on the Twitch platform, potentially leading to unauthorized streaming, channel manipulation, or exposure of sensitive user information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Twitch client credentials (Client ID and Client Secret).\n2. Attempt to obtain an access token and then use it to query channel information or update stream settings via the Twitch API.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Twitch client credentials immediately and generate new ones. Review Twitch audit logs for any unauthorized activities."
  },
  "TwitchAccessToken": {
    "service": "Twitch",
    "category": "Live Streaming Service",
    "impact": "Unauthorized access to and modification of data on the Twitch platform on behalf of a user, potentially leading to unauthorized streaming, channel manipulation, or exposure of sensitive user information.",
    "severity": "High",
    "poc_template": "1. Locate exposed Twitch access token.\n2. Use the token to query user data, update channel settings, or perform actions on behalf of the user via the Twitch API.\n3. Verify successful API interaction.",
    "remediation": "Revoke the exposed Twitch access token immediately through Twitch's security settings for connected apps."
  },
  "Twitter": {
    "service": "Twitter",
    "category": "Social Media Platform",
    "impact": "Unauthorized access to and interaction with Twitter's platform programmatically, potentially leading to unauthorized tweet posting, account impersonation, data scraping of public or private user data, or manipulation of Twitter functionalities.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Twitter API keys/tokens (Bearer Token, Access Token, etc.).\n2. Use the token to make an API request (e.g., tweet, retrieve user timeline, access direct messages if permission allows).\n3. Verify successful API interaction and potential unauthorized activity.",
    "remediation": "Immediately revoke the exposed Twitter API keys/tokens through the Twitter Developer Portal. Review associated account activity for any unauthorized actions."
  },
  "TwitterConsumerkey": {
    "service": "Twitter",
    "category": "Social Media Platform",
    "impact": "Unauthorized authentication to Twitter and performance of actions on behalf of users, potentially leading to unauthorized tweet posting, account impersonation, data scraping, or manipulation of Twitter functionalities.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Twitter Consumer Keys and Secrets.\n2. Attempt to obtain an OAuth token using these credentials and then use it to perform actions like tweeting or accessing user data via the Twitter API.\n3. Verify successful API interaction.",
    "remediation": "Immediately revoke the exposed Twitter Consumer Keys and Secrets through the Twitter Developer Portal. Review associated account activity for any unauthorized actions."
  },
  "Tyntec": {
    "service": "Tyntec",
    "category": "Communication APIs",
    "impact": "Unauthorized access to and management of messaging, voice, and phone number verification services, potentially leading to unauthorized message sending, call manipulation, or resource abuse.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Tyntec API keys.\n2. Attempt to send a test SMS message or verify a phone number using the Tyntec API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Tyntec API keys immediately."
  },
  "Typeform": {
    "service": "Typeform",
    "category": "Form & Survey Creation",
    "impact": "Unauthorized access to and management of forms and responses, potentially leading to manipulation of survey questions, exposure of sensitive responses, or disruption of data collection.",
    "severity": "High",
    "poc_template": "1. Locate exposed Typeform API keys.\n2. Attempt to list forms or retrieve responses using the Typeform API with the found keys.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Typeform API keys immediately."
  },
  "Typetalk": {
    "service": "Typetalk",
    "category": "Chat App",
    "impact": "Unauthorized ability to read potentially sensitive chat messages, leading to eavesdropping on private conversations or exposure of confidential team communications.",
    "severity": "High",
    "poc_template": "1. Locate exposed Typetalk API keys.\n2. Attempt to list topics or retrieve messages from a chat channel using the Typetalk API with the found keys.\n3. Verify successful data access.",
    "remediation": "Rotate the Typetalk API keys immediately."
  },
  "UPCDatabase": {
    "service": "UPCDatabase",
    "category": "Product Information Database",
    "impact": "Unauthorized querying of product details, potentially leading to excessive API usage charges or data scraping of product information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed UPCDatabase API key.\n2. Use the key to query product details for a UPC code via the UPCDatabase API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the UPCDatabase API key immediately."
  },
  "URI": {
    "service": "Generic URI with Embedded Credentials",
    "category": "Access Control",
    "impact": "Unauthorized access to web resources without explicit user interaction, potentially exposing sensitive data, allowing unauthorized actions, or providing an entry point for further attacks if the URI points to an administrative endpoint.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed URL with embedded credentials (e.g., `https://username:password@example.com/api`).\n2. Attempt to access the resource directly via a web browser or `curl`.\n3. Verify successful unauthorized access and assess the type of information or functionality exposed.",
    "remediation": "Immediately remove or revoke the credentials embedded in the URL. If the resource is sensitive, rotate the credentials and implement proper authentication mechanisms (e.g., OAuth, API keys in headers) instead of embedding them in the URI. Ensure that such URIs are never exposed in public repositories, logs, or client-side code."
  },
  "Ubidots": {
    "service": "Ubidots",
    "category": "IoT Platform",
    "impact": "Unauthorized access to and manipulation of data from IoT devices, potentially leading to device manipulation, data theft from IoT sensors, or disruption of IoT applications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Ubidots tokens.\n2. Attempt to access or manipulate data from IoT devices (e.g., read sensor data, send commands to actuators) using the Ubidots API with the found tokens.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Ubidots tokens immediately. Review Ubidots audit logs for unauthorized activities."
  },
  "Uclassify": {
    "service": "Uclassify",
    "category": "Text Classification Service",
    "impact": "Unauthorized classification of text into various categories, potentially leading to excessive API usage charges or the processing of sensitive text for classification without consent.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Uclassify API keys.\n2. Use the keys to classify sample text (e.g., for sentiment, topic) via the Uclassify API.\n3. Verify successful text classification.",
    "remediation": "Rotate the Uclassify API keys immediately."
  },
  "UnifyID": {
    "service": "UnifyID",
    "category": "Human Detection Services",
    "impact": "Unauthorized utilization of human detection services, potentially leading to excessive API usage charges or bypassing security mechanisms designed to verify human presence.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed UnifyID API keys.\n2. Use the keys to make a human detection request via the UnifyID API.\n3. Verify successful API interaction.",
    "remediation": "Rotate the UnifyID API keys immediately."
  },
  "Unplugg": {
    "service": "Unplugg",
    "category": "Forecasting & Data Analysis",
    "impact": "Unauthorized access to and manipulation of forecast data, potentially leading to data manipulation, exposure of sensitive predictive insights, or disruption of data analysis workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Unplugg API keys.\n2. Attempt to retrieve or modify forecast data using the Unplugg API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Unplugg API keys immediately."
  },
  "Unsplash": {
    "service": "Unsplash",
    "category": "Stock Photography Website",
    "impact": "Unauthorized access to and modification of Unsplash data, potentially leading to excessive API usage charges, data scraping of stock photography, or misuse of content.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Unsplash API keys.\n2. Use the keys to search for photos or access photo details via the Unsplash API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Unsplash API keys immediately."
  },
  "Uplead": {
    "service": "Uplead",
    "category": "B2B Contact Data Provider",
    "impact": "Unauthorized access to and management of B2B contact data, potentially leading to excessive API usage charges or data scraping for lead generation or reconnaissance.",
    "severity": "High",
    "poc_template": "1. Locate exposed Uplead API keys.\n2. Use the keys to search for B2B contacts or retrieve company data via the Uplead API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Uplead API keys immediately."
  },
  "UploadCare": {
    "service": "UploadCare",
    "category": "File Upload & Transformation",
    "impact": "Unauthorized management and access to files, potentially leading to unauthorized file uploads, deletion of legitimate files, or manipulation of file transformations.",
    "severity": "High",
    "poc_template": "1. Locate exposed UploadCare keys.\n2. Attempt to upload a file, list existing files, or apply transformations using the UploadCare API with the found keys.\n3. Verify successful file manipulation.",
    "remediation": "Revoke and regenerate the UploadCare keys immediately."
  },
  "UptimeRobot": {
    "service": "UptimeRobot",
    "category": "Website Monitoring Service",
    "impact": "Unauthorized management and monitoring of websites and services, potentially leading to disabling alerts, altering uptime checks, or exposing sensitive website performance data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed UptimeRobot API keys.\n2. Use the keys to list monitors or modify monitoring settings via the UptimeRobot API.\n3. Verify successful API interaction.",
    "remediation": "Rotate the UptimeRobot API keys immediately."
  },
  "Upwave": {
    "service": "Upwave",
    "category": "Project Management Tool",
    "impact": "Unauthorized access to and management of project data, potentially leading to project disruption, data theft, or exposure of sensitive task details.",
    "severity": "High",
    "poc_template": "1. Locate exposed Upwave API keys.\n2. Attempt to list projects, create new tasks, or modify project boards using the Upwave API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Upwave API keys immediately."
  },
  "Urlscan": {
    "service": "Urlscan",
    "category": "Website Scanning & Analysis",
    "impact": "Unauthorized interaction with the Urlscan service programmatically, potentially leading to excessive API usage charges or submitting malicious URLs for analysis and exposing scan results.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Urlscan API keys.\n2. Use the keys to submit a URL for scanning or retrieve scan results via the Urlscan API.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Urlscan API keys immediately."
  },
  "UserStack": {
    "service": "UserStack",
    "category": "User Agent & Tech Stack Data",
    "impact": "Unauthorized access to detailed information about the technology stack used by websites, potentially leading to excessive API usage charges or data scraping for reconnaissance or competitive intelligence.",
    "severity": "Low",
    "poc_template": "1. Locate exposed UserStack API keys.\n2. Use the keys to retrieve tech stack information for a website via the UserStack API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the UserStack API keys immediately."
  },
  "Userflow": {
    "service": "Userflow",
    "category": "User Onboarding Experiences",
    "impact": "Unauthorized access to and modification of user onboarding data and workflows, potentially leading to manipulation of user experiences, exposure of sensitive user behavior data, or disruption of onboarding processes.",
    "severity": "High",
    "poc_template": "1. Locate exposed Userflow API keys.\n2. Attempt to list flows, track user events, or modify user attributes using the Userflow API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Userflow API keys immediately."
  },
  "VagrantCloudPersonalToken": {
    "service": "Vagrant Cloud",
    "category": "Development Environment Management",
    "impact": "Unauthorized authentication and interaction with the Vagrant Cloud API, potentially leading to management of development environments, access to private boxes, or distribution of unauthorized box versions, impacting development workflows and security.",
    "severity": "High",
    "poc_template": "1. Locate exposed Vagrant Cloud personal token.\n2. Configure Vagrant CLI with the found token.\n3. Attempt to list boxes, create new versions, or manage collaborators.\n4. Verify successful access and resource manipulation.",
    "remediation": "Revoke the exposed Vagrant Cloud personal token immediately and generate a new one, ensuring it has minimal necessary permissions."
  },
  "VatLayer": {
    "service": "VatLayer",
    "category": "VAT Validation & Rate Data",
    "impact": "Unauthorized access to VAT number validation and VAT rate data, potentially leading to excessive API usage charges or misuse of the service for financial reconnaissance or fraud.",
    "severity": "Low",
    "poc_template": "1. Locate exposed VatLayer keys.\n2. Use the keys to validate a VAT number or retrieve VAT rates via the VatLayer API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the VatLayer keys immediately."
  },
  "Vbout": {
    "service": "Vbout",
    "category": "Marketing Automation Platform",
    "impact": "Unauthorized access to and management of marketing data and campaigns, potentially leading to unauthorized email/SMS sending, lead manipulation, or exposure of sensitive customer data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Vbout API keys.\n2. Attempt to list contacts, send a test campaign, or modify marketing automation workflows using the Vbout API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Vbout API keys immediately."
  },
  "Vercel": {
    "service": "Vercel",
    "category": "Frontend Cloud Platform",
    "impact": "Unauthorized access to and management of Vercel projects and deployments, potentially leading to unauthorized code deployments, website defacement, or access to sensitive environment variables, compromising web applications and content.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Vercel API keys.\n2. Configure Vercel CLI with the found key.\n3. Attempt to list projects, deploy a new project, or access environment variables.\n4. Verify successful administrative control over Vercel resources.",
    "remediation": "Immediately revoke the exposed Vercel API key and generate a new one, ensuring it has minimal necessary permissions. Review Vercel audit logs for any unauthorized activities."
  },
  "Verifier": {
    "service": "Verifier",
    "category": "Credential Verification Service",
    "impact": "Unauthorized utilization of a service to verify the authenticity of a credential, potentially leading to resource abuse or enabling reconnaissance against user identities.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Verifier tokens.\n2. Use the tokens to attempt to validate a test user identity via the Verifier API.\n3. Verify successful validation result.",
    "remediation": "Rotate the Verifier tokens immediately."
  },
  "Verimail": {
    "service": "Verimail",
    "category": "Email Verification Service",
    "impact": "Unauthorized access to and utilization of email verification services, potentially leading to excessive API usage charges or the misuse of the service for lead generation or spam list validation.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Verimail keys.\n2. Use the keys to verify an email address via the Verimail API.\n3. Verify successful verification result.",
    "remediation": "Rotate the Verimail keys immediately."
  },
  "Veriphone": {
    "service": "Veriphone",
    "category": "Phone Number Validation",
    "impact": "Unauthorized access to phone number validation services, potentially leading to excessive API usage charges or misuse of the service for reconnaissance or spamming purposes.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Veriphone API keys.\n2. Use the keys to validate a phone number via the Veriphone API.\n3. Verify successful validation result.",
    "remediation": "Rotate the Veriphone API keys immediately."
  },
  "VersionEye": {
    "service": "VersionEye",
    "category": "Dependency Monitoring",
    "impact": "Unauthorized access to and management of project dependencies and vulnerability alerts, potentially leading to exposure of sensitive project security data or manipulation of dependency monitoring configurations.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed VersionEye API keys.\n2. Attempt to list projects or retrieve vulnerability reports using the VersionEye API with the found keys.\n3. Verify successful data access.",
    "remediation": "Rotate the VersionEye API keys immediately."
  },
  "Viewneo": {
    "service": "Viewneo",
    "category": "Digital Signage Platform",
    "impact": "Unauthorized access to and management of digital signage content and settings, potentially leading to unauthorized content display, content tampering, or disruption of digital signage networks.",
    "severity": "High",
    "poc_template": "1. Locate exposed Viewneo API keys.\n2. Attempt to list content, modify playlists, or update device settings using the Viewneo API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Viewneo API keys immediately."
  },
  "VirusTotal": {
    "service": "VirusTotal",
    "category": "Malware Analysis Service",
    "impact": "Unauthorized access to and integration with VirusTotal's analysis services, potentially leading to excessive API usage charges, submission of malicious files/URLs for analysis, or exposure of sensitive analysis results.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed VirusTotal API keys.\n2. Use the keys to submit a file/URL for analysis or retrieve analysis reports via the VirusTotal API.\n3. Verify successful API interaction.",
    "remediation": "Rotate the VirusTotal API keys immediately."
  },
  "VisualCrossing": {
    "service": "Visual Crossing",
    "category": "Weather Data Services",
    "impact": "Unauthorized access to weather data services, potentially leading to excessive API usage charges or data scraping of meteorological information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Visual Crossing API keys.\n2. Use the keys to fetch weather data or forecasts via the Visual Crossing API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Visual Crossing API keys immediately."
  },
  "Voiceflow": {
    "service": "Voiceflow",
    "category": "AI Service (Customer Transaction)",
    "impact": "Unauthorized access to customer data via the AI service, potentially leading to privacy breaches, manipulation of customer interactions, or exposure of sensitive conversational data.",
    "severity": "High",
    "poc_template": "1. Locate exposed Voiceflow API keys.\n2. Attempt to access customer data or conversational logs using the Voiceflow API with the found keys.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Voiceflow API keys immediately."
  },
  "Voicegain": {
    "service": "Voicegain",
    "category": "Speech Recognition & NLP",
    "impact": "Unauthorized access to and management of speech recognition and natural language processing services, potentially leading to excessive API usage charges, transcription of sensitive audio, or misuse of NLP capabilities.",
    "severity": "High",
    "poc_template": "1. Locate exposed Voicegain API keys.\n2. Attempt to transcribe audio or perform NLP tasks using the Voicegain API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Voicegain API keys immediately."
  },
  "VoodooSMS": {
    "service": "VoodooSMS",
    "category": "SMS Sending Service",
    "impact": "Unauthorized sending of SMS messages and checking of account balance, potentially leading to spamming, phishing attempts, or significant financial cost due to message charges.",
    "severity": "High",
    "poc_template": "1. Locate exposed VoodooSMS API keys.\n2. Attempt to send a test SMS message or check account balance using the VoodooSMS API with the found keys.\n3. Verify successful message delivery.",
    "remediation": "Revoke and regenerate the VoodooSMS API keys immediately."
  },
  "Vouchery": {
    "service": "Vouchery",
    "category": "Promotional & Loyalty Platform",
    "impact": "Unauthorized access to and management of promotional and loyalty campaigns, potentially leading to unauthorized coupon/voucher creation, fraudulent redemptions, or exposure of sensitive marketing strategies.",
    "severity": "High",
    "poc_template": "1. Locate exposed Vouchery API keys.\n2. Attempt to create a new voucher, redeem a voucher, or list campaigns using the Vouchery API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Vouchery API keys immediately."
  },
  "Vpnapi": {
    "service": "Vpnapi",
    "category": "IP Address & VPN Detection",
    "impact": "Unauthorized access to information about IP addresses, including geolocation and VPN detection, potentially leading to excessive API usage charges or data scraping for reconnaissance.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Vpnapi keys.\n2. Use the keys to retrieve IP address information or detect VPN usage via the Vpnapi.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Vpnapi keys immediately."
  },
  "VultrApiKey": {
    "service": "Vultr",
    "category": "Cloud Service Provider",
    "impact": "Unauthorized access to and management of cloud computing, storage, and networking services, potentially leading to resource abuse, data exfiltration, or denial of service for hosted applications.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Vultr API key.\n2. Configure Vultr CLI (`vultr-cli`) with the found key.\n3. Attempt to list instances, create new servers, or manage DNS records.\n4. Verify successful administrative control over Vultr resources.",
    "remediation": "Immediately revoke the exposed Vultr API key and generate a new one, ensuring it has minimal necessary permissions."
  },
  "Vyte": {
    "service": "Vyte",
    "category": "Scheduling Platform",
    "impact": "Unauthorized access to and management of events, potentially leading to manipulation of schedules, exposure of sensitive meeting details, or disruption of scheduling services.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Vyte API keys.\n2. Attempt to list events or create a new event using the Vyte API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Vyte API keys immediately."
  },
  "WalkScore": {
    "service": "Walkscore",
    "category": "Walkability Score API",
    "impact": "Unauthorized access to Walkscore's services for retrieving walkability scores and related data, potentially leading to excessive API usage charges or data scraping of location-based lifestyle information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Walkscore API keys.\n2. Use the keys to retrieve a walkability score for an address via the Walkscore API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Walkscore API keys immediately."
  },
  "WeatherBit": {
    "service": "Weatherbit",
    "category": "Weather Data Service",
    "impact": "Unauthorized access to weather data and related services, potentially leading to excessive API usage charges or data scraping of meteorological information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Weatherbit API keys.\n2. Use the keys to fetch current weather data or forecasts via the Weatherbit API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Weatherbit API keys immediately."
  },
  "WeatherStack": {
    "service": "Weatherstack",
    "category": "Weather Service",
    "impact": "Unauthorized access to real-time weather information, potentially leading to excessive API usage charges or data scraping of meteorological information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Weatherstack API keys.\n2. Use the keys to fetch weather data for a location via the Weatherstack API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Weatherstack API keys immediately."
  },
  "Web3Storage": {
    "service": "Web3.storage",
    "category": "Decentralized Storage Solutions",
    "impact": "Unauthorized access to and management of stored data on decentralized storage, potentially leading to unauthorized data uploads, deletion of legitimate data, or resource abuse on the IPFS network.",
    "severity": "High",
    "poc_template": "1. Locate exposed Web3.storage API keys.\n2. Attempt to upload a file or retrieve stored data using the Web3.storage API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Web3.storage API keys immediately."
  },
  "WebScraper": {
    "service": "WebScraper",
    "category": "Web Scraping Service",
    "impact": "Unauthorized creation, management, and running of sitemaps for web scraping tasks, potentially leading to excessive API usage charges, unauthorized data extraction from websites, or exposure of sensitive scraping configurations.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed WebScraper API keys.\n2. Use the keys to list sitemaps, create a new sitemap, or run a scraping job via the WebScraper API.\n3. Verify successful API interaction.",
    "remediation": "Rotate the WebScraper API keys immediately."
  },
  "Webex": {
    "service": "Webex",
    "category": "Collaboration Tool",
    "impact": "Unauthorized access to and management of video conferencing, online meetings, screen share, and webinars, potentially leading to unauthorized meeting access, eavesdropping, or disruption of communication services.",
    "severity": "High",
    "poc_template": "1. Locate exposed Webex API keys.\n2. Attempt to list meetings, create a new meeting, or send messages in a Webex space using the Webex API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Webex API keys immediately. Review Webex audit logs for unauthorized activities."
  },
  "Webflow": {
    "service": "Webflow",
    "category": "Web Design Tool",
    "impact": "Unauthorized access to and manipulation of data within Webflow projects, potentially leading to website defacement, content modification, or disruption of web design workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Webflow API keys.\n2. Attempt to list projects, modify collection items, or publish sites using the Webflow API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Webflow API keys immediately."
  },
  "Webscraping": {
    "service": "Webscraping API",
    "category": "Web Scraping Service",
    "impact": "Unauthorized access to web scraping services to extract data from websites, potentially leading to excessive API usage charges or data exfiltration from target websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Webscraping API keys.\n2. Use the keys to perform a web scraping request via a Webscraping API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Webscraping API keys immediately."
  },
  "Websitepulse": {
    "service": "Websitepulse",
    "category": "Website & Server Monitoring",
    "impact": "Unauthorized access to and management of monitoring configurations, potentially leading to disabling checks, altering alerts, or exposing sensitive website and server performance data.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Websitepulse keys and IDs.\n2. Attempt to list monitors or modify monitoring settings using the Websitepulse API with the found credentials.\n3. Verify successful API interaction.",
    "remediation": "Rotate the Websitepulse keys and IDs immediately."
  },
  "WeightsAndBiases": {
    "service": "Weights & Biases",
    "category": "Machine Learning Operations (MLOps) Platform",
    "impact": "Unauthorized access to track experiments, version datasets, evaluate model performance, and collaborate with team members, potentially leading to exposure of sensitive ML research, manipulation of experiment results, or intellectual property theft.",
    "severity": "High",
    "poc_template": "1. Locate exposed Weights & Biases API keys.\n2. Attempt to list projects, log new experiment runs, or access dataset versions using the Weights & Biases API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Weights & Biases API keys immediately."
  },
  "Whoxy": {
    "service": "Whoxy",
    "category": "WHOIS Data Service",
    "impact": "Unauthorized querying of WHOIS data for domain names, potentially leading to excessive API usage charges or data scraping for reconnaissance or competitive intelligence.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Whoxy API keys.\n2. Use the keys to query WHOIS information for a domain name via the Whoxy API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Whoxy API keys immediately."
  },
  "Wistia": {
    "service": "Wistia",
    "category": "Video Hosting Platform",
    "impact": "Unauthorized access to and management of video content and account settings, potentially leading to unauthorized video deletion, content manipulation, or disruption of video hosting services.",
    "severity": "High",
    "poc_template": "1. Locate exposed Wistia API keys.\n2. Attempt to list projects, upload videos, or modify video settings using the Wistia API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Wistia API keys immediately."
  },
  "Wiz": {
    "service": "Wiz",
    "category": "Cloud Security Platform",
    "impact": "Unauthorized access to and management of cloud security configurations, potentially leading to disabling security policies, manipulating vulnerability assessments, or exposing sensitive cloud asset inventory.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Wiz credentials.\n2. Attempt to query cloud assets, list vulnerabilities, or modify security policies via the Wiz API.\n3. Verify successful administrative access and security data manipulation.",
    "remediation": "Revoke the exposed Wiz credentials and generate new, strong credentials immediately. Review audit logs for unauthorized activities."
  },
  "Worksnaps": {
    "service": "Worksnaps",
    "category": "Time Tracking Service (Remote Work)",
    "impact": "Unauthorized access to and management of project data and time tracking information, potentially leading to inaccurate billing, financial fraud, or exposure of sensitive remote work activity.",
    "severity": "High",
    "poc_template": "1. Locate exposed Worksnaps API keys.\n2. Attempt to retrieve time entries, project details, or screenshots (if available) using the Worksnaps API with the found keys.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke and regenerate the Worksnaps API keys immediately."
  },
  "Workstack": {
    "service": "Workstack",
    "category": "Project Management Tool",
    "impact": "Unauthorized access to and modification of project data and management of tasks, potentially leading to project disruption, data theft, or exposure of sensitive task details.",
    "severity": "High",
    "poc_template": "1. Locate exposed Workstack API keys.\n2. Attempt to list projects, create tasks, or modify project details using the Workstack API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Workstack API keys immediately."
  },
  "WorldCoinIndex": {
    "service": "WorldCoinIndex",
    "category": "Cryptocurrency Market Data Provider",
    "impact": "Unauthorized access to cryptocurrency market data and other information, potentially leading to excessive API usage charges or data scraping of market information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed WorldCoinIndex API keys.\n2. Use the keys to fetch cryptocurrency market data via the WorldCoinIndex API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the WorldCoinIndex API keys immediately."
  },
  "WorldWeather": {
    "service": "Worldweather",
    "category": "Weather Data Services",
    "impact": "Unauthorized access to various weather data endpoints, potentially leading to excessive API usage charges or data scraping of meteorological information.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Worldweather keys.\n2. Use the keys to fetch weather data for a location via the Worldweather API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Worldweather keys immediately."
  },
  "Wrike": {
    "service": "Wrike",
    "category": "Collaborative Work Management Platform",
    "impact": "Unauthorized access to and modification of data within Wrike, potentially leading to project disruption, data theft, or exposure of sensitive work management information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Wrike API keys.\n2. Attempt to list projects, create tasks, or modify workflows using the Wrike API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Wrike API keys immediately. Review Wrike audit logs for any unauthorized activities."
  },
  "XAI": {
    "service": "xAI",
    "category": "AI Company",
    "impact": "Unauthorized access to and usage of xAI's AI models and services, potentially leading to resource abuse, generation of harmful content, or exposure of proprietary AI interactions and research.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed xAI API key.\n2. Attempt to make a request to an xAI model (if an API is publicly available) using the found key.\n3. Verify successful API interaction and response.",
    "remediation": "Revoke and regenerate the xAI API key immediately."
  },
  "Yandex": {
    "service": "Yandex",
    "category": "Technology Company (ML-powered services)",
    "impact": "Unauthorized access to and interaction with various Yandex services, potentially leading to resource abuse, data exfiltration from cloud services, or misuse of machine learning capabilities.",
    "severity": "High",
    "poc_template": "1. Locate exposed Yandex API keys.\n2. Attempt to use the keys to interact with a Yandex service (e.g., search, translate, cloud functions) via their API.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Yandex API keys immediately."
  },
  "Yelp": {
    "service": "Yelp",
    "category": "Business & Review Platform",
    "impact": "Unauthorized access to Yelp's business data and services, potentially leading to data breaches (e.g., scraping business contact info, reviews) and misuse of Yelp's services, such as injecting fake reviews or manipulating business information.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Yelp API keys.\n2. Use the keys to search for businesses or retrieve business details via the Yelp API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Yelp API keys immediately."
  },
  "YouNeedABudget": {
    "service": "YouNeedABudget (YNAB)",
    "category": "Budgeting Tool",
    "impact": "Unauthorized access to and modification of a user's financial data, potentially leading to financial fraud, unauthorized transaction logging, or exposure of sensitive personal financial information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed YouNeedABudget API keys.\n2. Attempt to list budgets, retrieve transaction history, or add new transactions using the YouNeedABudget API with the found keys.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke and regenerate the YouNeedABudget API keys immediately. Review all budget activities for unauthorized changes."
  },
  "YouSign": {
    "service": "Yousign",
    "category": "Electronic Signature Service",
    "impact": "Unauthorized access to and management of documents for electronic signatures, potentially leading to unauthorized document signing, tampering with contracts, or exposure of sensitive e-signature data.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Yousign API keys.\n2. Attempt to send a document for signature or retrieve signature request details using the Yousign API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the Yousign API keys immediately."
  },
  "YoutubeApiKey": {
    "service": "YouTube Data API",
    "category": "Video Platform API",
    "impact": "Unauthorized access to various functionalities of the YouTube Data API, potentially leading to excessive API usage charges, data scraping of video details, manipulation of playlists, or unauthorized video uploads if permissions allow.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed YouTube API Key.\n2. Use the key to retrieve video details, search for videos, or access channel information via the YouTube Data API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the YouTube API Key immediately through the Google Cloud Console."
  },
  "ZenRows": {
    "service": "ZenRows",
    "category": "Web Scraping API",
    "impact": "Unauthorized access to and scraping of web data, potentially leading to excessive API usage charges or data exfiltration from target websites.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ZenRows API keys.\n2. Use the keys to perform a web scraping request via the ZenRows API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ZenRows API keys immediately."
  },
  "ZendeskApi": {
    "service": "Zendesk",
    "category": "Customer Service Platform",
    "impact": "Unauthorized access to and modification of customer service data, potentially leading to data breaches, support ticket manipulation, or exposure of sensitive customer interactions.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Zendesk API tokens.\n2. Attempt to list tickets, create new tickets, or retrieve customer details using the Zendesk API with the found tokens.\n3. Verify successful data access or manipulation.",
    "remediation": "Revoke and regenerate the Zendesk API tokens immediately."
  },
  "ZenkitAPI": {
    "service": "Zenkit",
    "category": "Collaborative SaaS Platform",
    "impact": "Unauthorized access to and interaction with Zenkit's services programmatically, potentially leading to project disruption, data theft, or exposure of sensitive project management and database content.",
    "severity": "High",
    "poc_template": "1. Locate exposed Zenkit API keys.\n2. Attempt to list collections, create items, or modify data within Zenkit using the Zenkit API with the found keys.\n3. Verify successful data manipulation.",
    "remediation": "Revoke and regenerate the Zenkit API keys immediately."
  },
  "Zenscrape": {
    "service": "Zenscrape",
    "category": "Web Scraping Service",
    "impact": "Unauthorized access to and scraping of data from websites, potentially leading to excessive API usage charges or data exfiltration from target web pages.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed Zenscrape API keys.\n2. Use the keys to perform a web scraping request via the Zenscrape API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Zenscrape API keys immediately."
  },
  "Zenserp": {
    "service": "Zenserp",
    "category": "SERP API",
    "impact": "Unauthorized access to search engine results page (SERP) data programmatically, potentially leading to excessive API usage charges or data scraping for competitive intelligence.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Zenserp API keys.\n2. Use the keys to retrieve SERP data for a search query via the Zenserp API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Zenserp API keys immediately."
  },
  "Zeplin": {
    "service": "Zeplin",
    "category": "UI Design & Development Collaboration",
    "impact": "Unauthorized access to and modification of project data, potentially leading to intellectual property theft of design assets, manipulation of design specifications, or disruption of design-to-development workflows.",
    "severity": "High",
    "poc_template": "1. Locate exposed Zeplin API keys.\n2. Attempt to list projects, access design components, or retrieve style guides using the Zeplin API with the found keys.\n3. Verify successful data access.",
    "remediation": "Revoke and regenerate the Zeplin API keys immediately."
  },
  "ZeroTier": {
    "service": "ZeroTier",
    "category": "Network Virtualization",
    "impact": "Unauthorized management and control of secure and flexible network connections, potentially leading to unauthorized network access, device enrollment, or configuration changes, compromising network security.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed ZeroTier API keys.\n2. Attempt to list networks, add/remove devices from a network, or modify network configurations using the ZeroTier API with the found keys.\n3. Verify successful API interaction and control over the network.",
    "remediation": "Revoke and regenerate the ZeroTier API keys immediately."
  },
  "Zerobounce": {
    "service": "Zerobounce",
    "category": "Email Validation & Verification",
    "impact": "Unauthorized access to and utilization of email validation and verification services, potentially leading to excessive API usage charges or the misuse of the service for lead generation or spam list validation.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Zerobounce API keys.\n2. Use the keys to validate an email address via the Zerobounce API.\n3. Verify successful validation result.",
    "remediation": "Rotate the Zerobounce API keys immediately."
  },
  "ZipAPI": {
    "service": "ZipAPI",
    "category": "ZIP Code Information Service",
    "impact": "Unauthorized access to and retrieval of ZIP code information, potentially leading to excessive API usage charges or data scraping of geographical data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed ZipAPI keys.\n2. Use the keys to retrieve ZIP code details for a given code via the ZipAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ZipAPI keys immediately."
  },
  "ZipBooks": {
    "service": "ZipBooks",
    "category": "Accounting Software Service",
    "impact": "Unauthorized access to and management of financial data, potentially leading to financial fraud, data manipulation, or exposure of sensitive financial records and client information.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed ZipBooks credentials.\n2. Attempt to retrieve or modify invoice data, expense records, or client information using the ZipBooks API.\n3. Verify successful data manipulation.",
    "remediation": "Revoke the exposed ZipBooks credentials and generate new, strong credentials immediately. Review all financial logs for unauthorized activities."
  },
  "ZipCodeAPI": {
    "service": "ZipCodeAPI",
    "category": "Zip Code Information & Distance Calculation",
    "impact": "Unauthorized access to zip code information and distance calculation services, potentially leading to excessive API usage charges or data scraping of geographical data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed ZipCodeAPI keys.\n2. Use the keys to retrieve zip code information or calculate distance between zip codes via the ZipCodeAPI.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the ZipCodeAPI keys immediately."
  },
  "Zipcodebase": {
    "service": "Zipcodebase",
    "category": "Postal Code Database",
    "impact": "Unauthorized access to a database of postal codes, potentially leading to excessive API usage charges or data scraping of geographical data.",
    "severity": "Low",
    "poc_template": "1. Locate exposed Zipcodebase API keys.\n2. Use the keys to query postal code information via the Zipcodebase API.\n3. Verify successful data retrieval.",
    "remediation": "Rotate the Zipcodebase API keys immediately."
  },
  "ZohoCRM": {
    "service": "Zoho CRM",
    "category": "CRM Platform",
    "impact": "Unauthorized access to sales, marketing, and customer support services through their REST API, potentially leading to data breaches, manipulation of customer records, or disruption of sales/marketing operations.",
    "severity": "Critical",
    "poc_template": "1. Locate exposed Zoho CRM API access token.\n2. Use the token to make an API request (e.g., list leads, create contacts, update deals) to Zoho CRM.\n3. Verify successful data access or manipulation.",
    "remediation": "Immediately revoke the exposed Zoho CRM API access token through Zoho CRM's API console. Review Zoho CRM audit logs for any unauthorized activities."
  },
  "ZonkaFeedback": {
    "service": "ZonkaFeedback",
    "category": "Customer Feedback Platform",
    "impact": "Unauthorized access to and management of feedback data, potentially leading to exposure of sensitive customer opinions, manipulation of survey results, or disruption of feedback collection.",
    "severity": "Medium",
    "poc_template": "1. Locate exposed ZonkaFeedback API token.\n2. Attempt to list surveys or retrieve feedback responses using the ZonkaFeedback API with the found token.\n3. Verify successful data access.",
    "remediation": "Rotate the ZonkaFeedback API token immediately."
  },
  "ZulipChat": {
    "service": "ZulipChat",
    "category": "Group Chat Application",
    "impact": "Unauthorized access to and management of various functionalities of the chat service, potentially leading to unauthorized message sending, eavesdropping on team conversations, or exposure of sensitive communication content.",
    "severity": "High",
    "poc_template": "1. Locate exposed ZulipChat API keys.\n2. Attempt to list streams/topics, send messages, or retrieve message history using the ZulipChat API with the found keys.\n3. Verify successful API interaction.",
    "remediation": "Revoke and regenerate the ZulipChat API keys immediately."
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
  
  return {
    title: `Exposed ${intelligence.service} Credentials in ${repoName}`,
    
    summary: `A ${intelligence.category.toLowerCase()} credential for ${intelligence.service} was found exposed in the public repository "${repoName}". The secret was detected in the file "${fileName}" and ${secretData.verified ? 'has been verified as active' : 'appears to be potentially active'}. This exposure poses a ${intelligence.severity.toLowerCase()} security risk to the organization.`,
    
    poc: `**Proof of Concept:**\n\n${intelligence.poc_template}\n\n**Location Details:**\n- Repository: ${secretData.repo_url}\n- File: ${secretData.file_path}\n- Commit: ${secretData.commit}\n- Detection Method: ${detector}\n- Verification Status: ${secretData.verified ? 'Verified Active' : 'Unverified'}`,
    
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
