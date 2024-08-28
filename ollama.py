import click
import json
import os
import email
import requests
import re
import logging
from colorama import Fore, Style, init
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from dotenv import load_dotenv
import ollama  # Import the ollama library

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Load environment variables from .env file
load_dotenv()

# Global variables for API keys
api_key = os.getenv('MXTOOLBOX_API_KEY')
ollama_api_url = "http://localhost:11434/api/generate"  # Ollama API endpoint

# Define prompt templates for different tasks
header_analysis_prompt_template = """Analyze the following email headers and perform these tasks:

1. Extract and list these important fields:
- From
- To
- Subject
- Date
- Received (summarize the path)
- Reply-To
- Return-Path
- X-Originating-IP
- Authentication-Results

2. Verify the sender's email address:
- Check for misspellings or variations of legitimate domains
- Note if it's a free email service for business communication
- Compare "From" with "Return-Path" and "Reply-To"

3. Examine the email's journey:
- Analyze "Received" fields
- Note any inconsistencies in server names, locations, or routing

4. Check IP addresses:
- Identify the originating IP
- Suggest investigating the IP (mention tools like whois.domaintools.com)
- Suggest checking for blacklisted IPs (mention mxtoolbox.com/blacklists.aspx)

5. Verify email authentication:
- Check SPF, DKIM, and DMARC results

6. Analyze date and time information:
- Check if the "Date" is recent and contextually appropriate
- Compare with "Received" timestamps

7. Note any unusual header fields

8. Provide a summary of findings and a risk assessment (low, medium, high)

Here are the headers:

{headers}

Provide your analysis as a Python dictionary. Include a 'user_friendly_summary' field with a simple explanation of the findings for non-technical users.
"""

phishing_detection_prompt_template = """You are an email security expert. Analyze this email body for phishing content:

{body}
"""

report_generation_prompt_template = """Based on the following email analysis results, create a detailed report with findings that summarizes the key points, assesses the risk, and provides recommendations for the user:

{analysis}

Your report should be structured with the following sections:
- Summary of Analysis
- Key Findings
- Risk Assessment
- Recommendations

Provide the report in plain text format.
"""

def run_ollama_prompt(prompt):
    """Run a prompt against the local Ollama instance."""
    try:
        response = ollama.chat(model='llama3:latest', messages=[{'role': 'user', 'content': prompt}])
        logging.debug(f"Raw response from Ollama: {response}")

        # Handle the case where the response is not a dictionary
        if isinstance(response, dict):
            return response['message']['content']  # Extract the text
        else:
            return response
    except ollama.ResponseError as e:
        click.echo(f"{Fore.RED}Error: Failed to connect to Ollama API. {str(e)}{Style.RESET_ALL}")
        return None
    except json.JSONDecodeError as e:
        click.echo(f"{Fore.RED}Error: Failed to parse JSON response from Ollama API. {str(e)}{Style.RESET_ALL}")
        return None

def extract_headers(email_source):
    msg = email.message_from_string(email_source)
    headers = []
    for key, value in msg.items():
        headers.append(f"{key}: {value}")
    return "\n".join(headers)

def process_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        email_source = file.read()
    msg = email.message_from_string(email_source)

    headers = extract_headers(email_source)

    body = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body.append(part.get_payload(decode=True).decode())
    else:
        body.append(msg.get_payload(decode=True).decode())

    return headers, body

def analyze_headers(headers):
    """Analyzes email headers using Ollama."""
    prompt = header_analysis_prompt_template.format(headers=headers)
    response = run_ollama_prompt(prompt)
    logging.debug(f"Raw GPT response:\n{response}")

    # Handle the case when the LLM returns a None response (empty response). 
    if response is None:
        return {"user_friendly_summary": "Unable to analyze headers.", "risk_assessment": "unknown"}

    # Handle the case when the LLM returns a text response instead of JSON 
    try:
        analysis_dict = json.loads(response)
    except json.JSONDecodeError:
        logging.warning(f"Error parsing JSON response from Ollama: {response}")
        # Try to extract key information from the text response
        analysis_dict = extract_key_info(response)

    # Ensure required fields are present
    if 'user_friendly_summary' not in analysis_dict:
        analysis_dict['user_friendly_summary'] = "Unable to generate a user-friendly summary."
    if 'risk_assessment' not in analysis_dict:
        analysis_dict['risk_assessment'] = "unknown"

    return analysis_dict

def extract_key_info(text):
    analysis_dict = {}
    lines = text.split('\n')
    current_key = None
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower().replace(' ', '_')
            value = value.strip()
            if key in ['user_friendly_summary', 'risk_assessment']:
                analysis_dict[key] = value
            elif not value:
                current_key = key
            else:
                analysis_dict[key] = value
        elif current_key:
            analysis_dict[current_key] = line.strip()
            current_key = None
    return analysis_dict



def phishing_detection(body_parts):
    """Detects phishing content in the email body using Ollama."""
    combined_body = "\n".join(body_parts)
    prompt = phishing_detection_prompt_template.format(body=combined_body)
    response = run_ollama_prompt(prompt)
    logging.debug(f"Raw GPT response:\n{response}")

    # Handle the case when the LLM returns a None response (empty response). 
    if response is None:
        return "Unable to detect phishing content."

    # Handle the case when the LLM returns a text response instead of JSON 
    try:
        # It's unlikely the phishing detection result will be JSON but add this for good measure
        phishing_result_dict = json.loads(response) 
        return phishing_result_dict.get("phishing_result", "Unable to detect phishing content.") 
    except json.JSONDecodeError:
        logging.warning(f"Error parsing JSON response from Ollama: {response}")
        return "Unable to detect phishing content."
    
    return response.strip()

def extract_key_info(text):
    analysis_dict = {}
    lines = text.split('\n')
    current_key = None
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower().replace(' ', '_')
            value = value.strip()
            if key in ['user_friendly_summary', 'risk_assessment']:
                analysis_dict[key] = value
            elif not value:
                current_key = key
            else:
                analysis_dict[key] = value
        elif current_key:
            analysis_dict[current_key] = line.strip()
            current_key = None
    return analysis_dict

def lookup_ip(ip, api_key):
    try:
        url = f'https://api.mxtoolbox.com/api/v1/Lookup/ptr/?argument={ip}'
        headers = {'Authorization': api_key}

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.RequestException as e:
        click.echo(f"{Fore.RED}Error: Failed to connect to MXToolbox API for IP lookup. {str(e)}{Style.RESET_ALL}")
        return None
    except json.JSONDecodeError:
        click.echo(f"{Fore.RED}Error: Unable to parse JSON response from MXToolbox API for IP lookup.{Style.RESET_ALL}")
        return None

def check_blacklist(ip, api_key):
    try:
        url = f'https://api.mxtoolbox.com/api/v1/Lookup/blacklist/?argument={ip}'
        headers = {'Authorization': api_key}

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        click.echo(f"{Fore.RED}Error: Failed to connect to MXToolbox API for blacklist check. {str(e)}{Style.RESET_ALL}")
        return None
    except json.JSONDecodeError:
        click.echo(f"{Fore.RED}Error: Unable to parse JSON response from MXToolbox API for blacklist check.{Style.RESET_ALL}")
        return None

def analyze_body(body_parts):
    patterns = [
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        r'\b(?:bank|login|secure|account|password)\b',
        r'\b(?:urgent|important|alert)\b',
    ]
    results = []
    for body in body_parts:
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(f"Potential phishing content detected: {pattern}")

    return results if results else ["No suspicious content detected."]

def generate_pdf_report(data, output_filename):
    c = canvas.Canvas(output_filename, pagesize=letter)
    width, height = letter
    y_position = height - 50

    def draw_text(text, x, y, font_size=12, leading=14):
        nonlocal y_position
        text_object = c.beginText(x, y)
        text_object.setFont("Helvetica", font_size)
        for line in text.split('\n'):
            text_object.textLine(line)
            y_position -= leading
        c.drawText(text_object)
        return y_position

    c.setFont("Helvetica-Bold", 16)
    y_position = draw_text("Email Analysis Report", 100, y_position)

    c.setFont("Helvetica-Bold", 14)
    y_position = draw_text(f"Risk Assessment: {data.get('risk_assessment', 'Unknown')}", 100, y_position - 20)

    c.setFont("Helvetica-Bold", 12)
    y_position = draw_text("User-Friendly Summary:", 100, y_position - 20)

    c.setFont("Helvetica", 10)
    summary = data.get('user_friendly_summary', "No summary available.")
    y_position = draw_text(summary, 120, y_position - 15, 10, 12)

    c.setFont("Helvetica-Bold", 12)
    y_position = draw_text("Detailed Analysis:", 100, y_position - 20)

    c.setFont("Helvetica", 10)
    for key, value in data.items():
        if key not in ['risk_assessment', 'user_friendly_summary']:
            if isinstance(value, dict):
                y_position = draw_text(f"{key.capitalize()}:", 100, y_position - 15, 10, 12)
                for sub_key, sub_value in value.items():
                    y_position = draw_text(f"{sub_key}: {sub_value}", 120, y_position - 12, 10, 12)
            else:
                y_position = draw_text(f"{key.capitalize()}: {value}", 100, y_position - 12, 10, 12)

        if y_position < 50:
            c.showPage()
            y_position = height - 50

    c.save()

def colorize_risk(risk):
    if risk.lower() == 'low':
        return f"{Fore.GREEN}{risk}{Style.RESET_ALL}"
    elif risk.lower() == 'medium':
        return f"{Fore.YELLOW}{risk}{Style.RESET_ALL}"
    elif risk.lower() == 'high':
        return f"{Fore.RED}{risk}{Style.RESET_ALL}"
    else:
        return risk

def display_analysis(analysis, body_analysis, ip_info, blacklist_check, phishing_result):
    print(f"\n{Fore.GREEN}Email Analysis Summary:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}User-Friendly Summary:{Style.RESET_ALL}")
    user_friendly_summary = analysis.get('user_friendly_summary', "No summary available.")
    print(f"{Fore.WHITE}{user_friendly_summary}{Style.RESET_ALL}")
    print("\n")

    print(f"{Fore.CYAN}Detailed Analysis for Experts:{Style.RESET_ALL}\n")

    for key, value in analysis.items():
        if key != 'user_friendly_summary':
            if isinstance(value, dict):
                print(f"{Fore.BLUE}{key.capitalize()}:{Style.RESET_ALL}")
                for sub_key, sub_value in value.items():
                    print(f"  {Fore.CYAN}- {sub_key}{Style.RESET_ALL}: {Fore.WHITE}{sub_value}{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}{key.capitalize()}{Style.RESET_ALL}: {Fore.WHITE}{value}{Style.RESET_ALL}")
        print("\n")

    print(f"{Fore.MAGENTA}Body Analysis Results:{Style.RESET_ALL}")
    for result in body_analysis:
        print(f"  {Fore.CYAN}- {result}{Style.RESET_ALL}")
    print("\n")

    # Display IP information
    if ip_info:
        print(f"{Fore.MAGENTA}IP Information:{Style.RESET_ALL}")
        for ip, info in ip_info.items():
            if info:
                print(f"  {Fore.BLUE}IP {ip}{Style.RESET_ALL}:")
                for key, value in info.items():
                    print(f"    {Fore.CYAN}- {key}{Style.RESET_ALL}: {Fore.WHITE}{value}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}No information available for IP {ip}.{Style.RESET_ALL}")
        print("\n")

    # Display blacklist check results
    if blacklist_check:
        print(f"{Fore.MAGENTA}Blacklist Check Results:{Style.RESET_ALL}")
        for ip, blacklist_info in blacklist_check.items():
            if blacklist_info:
                print(f"  {Fore.BLUE}IP {ip}{Style.RESET_ALL}:")
                for entry in blacklist_info.get('Failed', []):
                    print(f"    {Fore.RED}- {entry['Name']}: {entry['Info']}{Style.RESET_ALL}")
                for entry in blacklist_info.get('Passed', []):
                    print(f"    {Fore.GREEN}- {entry['Name']}: {entry['Info']}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.RED}No blacklist information available for IP {ip}.{Style.RESET_ALL}")
        print("\n")

    print(f"{Fore.MAGENTA}Phishing Detection Results:{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{phishing_result}{Style.RESET_ALL}")

    risk = analysis.get('risk_assessment', 'unknown')
    print(f"\n{Fore.MAGENTA}Risk Assessment: {colorize_risk(risk)}{Style.RESET_ALL}\n")

def generate_report_with_findings(analysis, phishing_result):
    formatted_analysis = json.dumps(analysis, indent=2)
    formatted_phishing_result = json.dumps(phishing_result, indent=2)
    prompt = f"""
    Based on the following email analysis results and phishing detection results, create a detailed report with findings that summarizes the key points, assesses the risk, and provides recommendations for the user:

    Email Analysis:
    {formatted_analysis}

    Phishing Detection Results:
    {formatted_phishing_result}

    Your report should be structured with the following sections:
    - Summary of Analysis
    - Key Findings (including phishing detection results)
    - Risk Assessment
    - Recommendations

    Provide the report as a Python dictionary with these sections as keys.
    """
    report = run_ollama_prompt(prompt)
    try:
        return json.loads(report)
    except json.JSONDecodeError:
        logging.error(f"Error parsing JSON response from Ollama for report generation: {report}")
        return {
            "summary_of_analysis": "Unable to generate summary.",
            "key_findings": "Unable to generate key findings.",
            "risk_assessment": "Unable to assess risk.",
            "recommendations": "Unable to provide recommendations."
        }

def display_report(report):
    print(f"\n{Fore.GREEN}Generated Report with Findings:{Style.RESET_ALL}\n")

    for section, content in report.items():
        print(f"{Fore.CYAN}{section.replace('_', ' ').title()}:{Style.RESET_ALL}")
        if isinstance(content, str):
            print(f"{Fore.WHITE}{content}{Style.RESET_ALL}\n")
        elif isinstance(content, list):
            for item in content:
                print(f"{Fore.WHITE}- {item}{Style.RESET_ALL}")
            print()
        elif isinstance(content, dict):
            for key, value in content.items():
                print(f"{Fore.WHITE}{key}: {value}{Style.RESET_ALL}")
            print()

def set_api_keys():
    global api_key
    if not api_key:
        api_key = click.prompt("Enter your MXToolbox API key", type=str)

    with open('.env', 'w') as f:
        f.write(f"MXTOOLBOX_API_KEY={api_key}\n")

    click.echo(f"{Fore.GREEN}API keys have been saved to .env file.{Style.RESET_ALL}")

def select_file():
    while True:
        file_path = click.prompt("Enter the path to your .eml file", type=click.Path(exists=True))
        if file_path.lower().endswith('.eml'):
            return file_path
        else:
            click.echo(f"{Fore.RED}Please provide a valid .eml file.{Style.RESET_ALL}")

@click.command()
@click.option('--ip-check', is_flag=True, help="Check IP against blacklists")
@click.option('--generate-pdf', is_flag=True, help="Generate a PDF report")
def run_email_analysis(ip_check, generate_pdf):
    """Runs the full email analysis process using Ollama."""
    if not api_key:
        click.echo(f"{Fore.YELLOW}API keys not set. Please set them first.{Style.RESET_ALL}")
        set_api_keys()

    file_path = select_file()

    headers, body_parts = process_file(file_path)
    analysis = analyze_headers(headers)

    body_analysis = analyze_body(body_parts)
    phishing_result = phishing_detection(body_parts)

    ip_info = {}
    blacklist_check = {}

    gpt_ips = analysis.get('ip_analysis', {}).get('originating_ips', [])
    if ip_check:
        for ip in gpt_ips:
            ip_info[ip] = lookup_ip(ip, api_key)
            blacklist_check[ip] = check_blacklist(ip, api_key)

    report = generate_report_with_findings(analysis, phishing_result)

    display_choice = click.prompt(
        f"\n{Fore.GREEN}What would you like to see?{Style.RESET_ALL}\n"
        "1. Analysis\n"
        "2. Report\n"
        "3. Both\n"
        "Enter your choice",
        type=click.Choice(['1', '2', '3']),
        default='3'
    )

    if display_choice in ['1', '3']:
        display_analysis(analysis, body_analysis, ip_info, blacklist_check, phishing_result)
    if display_choice in ['2', '3']:
        display_report(report)

    if generate_pdf:
        output_file = click.prompt("Enter the name for the PDF report", default="email_analysis_report.pdf")
        generate_pdf_report(analysis, output_file)
        click.echo(f"{Fore.GREEN}PDF report generated as '{output_file}'{Style.RESET_ALL}")

if __name__ == '__main__':
    run_email_analysis()