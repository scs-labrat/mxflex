
# MXFlex

**MXFlex** is a versatile, all-round email tool designed for cybersecurity professionals. The tool provides functionalities for analyzing domain records, managing SPF, DKIM, and DMARC records, performing email header and body analysis using local AI models, and generating homoglyph domains, among other features.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Main Menu](#main-menu)
  - [Whitehat Menu](#whitehat-menu)
  - [Blackhat Menu](#blackhat-menu)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [License](#license)

## Features

### Whitehat Tools

1. **Analyze Domain Records**: Analyze SPF, DKIM, and DMARC records for errors or security issues.
2. **SPF Record Management**: Generate, validate, and optimize SPF records.
3. **DKIM Key Generation and Configuration**: Generate DKIM key pairs and manage selectors.
4. **DMARC Policy Setup and Management**: Create and manage DMARC policies.
5. **Automated Testing and Validation**: Automated security testing for email infrastructure.
6. **Monitoring and Reporting**: Real-time monitoring and reporting tools for email security.
7. **Automated Analysis**: Integrates with ChatGPT for comprehensive analysis and recommendations.
8. **Ollama Self-Hosted Email Analyzer**: Perform email header and body analysis using a locally hosted Ollama AI model.

### Blackhat Tools

1. **Generate Homoglyph Domains**: Create similar-looking domains for phishing or security testing.
2. **Generate IP Logger Link**: Create IP logger links for tracking purposes.
3. **Generate Pretexting Messages**: Generate persuasive pretexting messages for social engineering.
4. **Banner Grabbing (SMTP and POP3)**: Retrieve server banners for enumeration.
5. **Enumerate SMTP Users**: Identify valid SMTP users using VRFY and RCPT TO commands.
6. **Brute-force SMTP Authentication**: Test SMTP authentication using a dictionary attack.
7. **Gemini Email Analyzer**: Analyze emails using the Gemini AI model.

## Installation

To install and run **MXFlex**, follow these steps:

1. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/mxflex.git
   cd mxflex
   ```

2. **Install the required Python packages**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up necessary environment variables**:

   - Create a `.env` file in the root directory.
   - Add your API keys and other environment variables:

   ```bash
   MXTOOLBOX_API_KEY=<your_mxtoolbox_api_key>
   GEMINI_API_KEY=<your_gemini_api_key>
   ```

4. **Download necessary browser drivers for Selenium**:
   - For example, download [ChromeDriver](https://sites.google.com/chromium.org/driver/) and place it in your desired directory.
   - Update the path in the script accordingly.

## Usage

To run the tool, navigate to the directory where `mxflex.py` is located and run:

```bash
python mxflex.py
```

### Main Menu

Upon running the script, you will be presented with the main menu:

- **1. Whitehat**: Access tools for cybersecurity defense and email security management.
- **2. Blackhat**: Access tools for offensive cybersecurity and penetration testing.
- **3. Exit**: Exit the program.

### Whitehat Menu

The Whitehat menu provides tools for analyzing and securing email systems:

- **Analyze Domain Records**: Check SPF, DKIM, and DMARC records.
- **SPF Record Management**: Generate, validate, and optimize SPF records.
- **DKIM Key Generation and Configuration**: Generate and manage DKIM keys.
- **DMARC Policy Setup and Management**: Set up and manage DMARC policies.
- **Automated Testing and Validation**: Coming soon.
- **Monitoring and Reporting**: Coming soon.
- **Automated Analysis**: Submit domain records to ChatGPT for analysis.
- **Ollama Self-Hosted Email Analyzer**: Analyze email headers and bodies using Ollama AI.

### Blackhat Menu

The Blackhat menu provides tools for offensive testing and research:

- **Generate Homoglyph Domains**: Generate domains that look similar to the target domain.
- **Generate IP Logger Link**: Create links that log the IP addresses of visitors.
- **Generate Pretexting Messages**: Create customized social engineering messages.
- **Banner Grabbing (SMTP/POP3)**: Collect server banners for further analysis.
- **Enumerate SMTP Users**: Use VRFY and RCPT TO commands to find valid email addresses.
- **Brute-force SMTP Authentication**: Attempt to brute-force email credentials.
- **Gemini Email Analyzer**: Analyze email content using OpenAI's GPT-4.

## Prerequisites

- **Python 3.8 or higher**
- **Required Python libraries**:
  - `click`
  - `colorama`
  - `requests`
  - `dnspython`
  - `fpdf`
  - `ollama`
  - `openai`
  - `selenium`
  - `beautifulsoup4`
  - `cryptography`
  - etc.

- **Browser Drivers** for Selenium (e.g., ChromeDriver)

## Configuration

1. **API Keys**: Ensure you have valid API keys set up in your environment.
2. **Local AI Models**: Ollama needs to be running locally for self-hosted analysis.
3. **SMTP and POP3 Servers**: Ensure you have the necessary permissions to perform banner grabbing and user enumeration.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
