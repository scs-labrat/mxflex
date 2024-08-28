import click
import json
import os
import email
import openai
import requests
import re
import logging
from colorama import Fore, Style, init
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from dotenv import load_dotenv

# Set up logging
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Load environment variables from .env file
load_dotenv()

# Global variables for API keys
api_key = os.getenv('MXTOOLBOX_API_KEY')
openai_api_key = os.getenv('OPENAI_API_KEY')

# Set OpenAI API key
openai.api_key = openai_api_key


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
    prompt = f"""Analyze the following email headers and perform these tasks:

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

    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are an expert in email security and header analysis. Provide detailed analysis for experts and a simple summary for beginners."},
            {"role": "user", "content": prompt}
        ]
    )

    raw_content = response['choices'][0]['message']['content']
    
    # Log the raw response
    logging.debug(f"Raw GPT response:\n{raw_content}")

    # Remove any markdown code block delimiters and language tags
    raw_content = raw_content.strip().lstrip('```').rstrip('```').strip()
    if raw_content.startswith('python'):
        raw_content = raw_content[6:].strip()

    # Attempt to parse as JSON
    try:
        analysis_dict = json.loads(raw_content)
    except json.JSONDecodeError:
        # If JSON parsing fails, attempt to evaluate as a Python dictionary
        try:
            # Use ast.literal_eval for safer evaluation
            import ast
            analysis_dict = ast.literal_eval(raw_content)
        except:
            # If both methods fail, attempt to extract key information
            analysis_dict = extract_key_info(raw_content)

    # Ensure required fields are present
    if 'user_friendly_summary' not in analysis_dict:
        analysis_dict['user_friendly_summary'] = "Unable to generate a user-friendly summary."
    if 'risk_assessment' not in analysis_dict:
        analysis_dict['risk_assessment'] = "unknown"

    return analysis_dict


def extract_key_info(text):
    # This function attempts to extract key information if parsing fails
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


def phishing_detection(body_parts):
    combined_body = "\n".join(body_parts)
    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are an email security expert. Analyze this email body for phishing content."},
            {"role": "user", "content": combined_body}
        ],
        max_tokens=1000,
        temperature=0.7
    )
    return response['choices'][0]['message']['content'].strip()


def deep_header_analysis(msg):
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Transfer-Encoding') == 'base64':
            print("Base64 encoded part detected.")
        if part.get_content_type() == 'application/pgp-encrypted':
            print("PGP encrypted content detected.")


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


def generate_report_with_findings(analysis):
    formatted_analysis = json.dumps(analysis, indent=2)

    prompt = f"""Based on the following email analysis results, create a detailed report with findings that summarizes the key points, assesses the risk, and provides recommendations for the user:

    {formatted_analysis}

    Your report should be structured with the following sections:
    - Summary of Analysis
    - Key Findings
    - Risk Assessment
    - Recommendations

    Provide the report in plain text format.
    """

    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are an expert in email security and report writing. Generate a comprehensive report based on the provided analysis."},
            {"role": "user", "content": prompt}
        ]
    )

    report = response['choices'][0]['message']['content'].strip()
    return report

def display_report(report):
    print(f"\n{Fore.GREEN}Generated Report with Findings:{Style.RESET_ALL}\n")
    
    # Split the report into sections based on a common structure like headings
    lines = report.split("\n")
    
    for line in lines:
        if "Summary of Analysis" in line:
            print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
        elif "Key Findings" in line:
            print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
        elif "Risk Assessment" in line:
            print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
        elif "Recommendations" in line:
            print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
        else:
            print(f"{Fore.WHITE}{line}{Style.RESET_ALL}")
    print("\n")


def set_api_keys():
    global api_key, openai_api_key
    if not api_key:
        api_key = click.prompt("Enter your MXToolbox API key", type=str)
    if not openai_api_key:
        openai_api_key = click.prompt("Enter your OpenAI API key", type=str)
    openai.api_key = openai_api_key

    with open('.env', 'w') as f:
        f.write(f"MXTOOLBOX_API_KEY={api_key}\n")
        f.write(f"OPENAI_API_KEY={openai_api_key}\n")

    click.echo(f"{Fore.GREEN}API keys have been saved to .env file.{Style.RESET_ALL}")


def select_file():
    while True:
        file_path = click.prompt("Enter the path to your .eml file", type=click.Path(exists=True))
        if file_path.lower().endswith('.eml'):
            return file_path
        else:
            click.echo(f"{Fore.RED}Please provide a valid .eml file.{Style.RESET_ALL}")


def analyze_email(file_path, ip_check, generate_pdf):
    click.echo(f"{Fore.YELLOW}Processing file: {file_path}{Style.RESET_ALL}")
    headers, body_parts = process_file(file_path)
    click.echo(f"{Fore.YELLOW}Analyzing headers...{Style.RESET_ALL}")
    analysis = analyze_headers(headers)

    body_analysis = analyze_body(body_parts)
    deep_header_analysis(email.message_from_string(headers))

    ip_info = {}
    blacklist_check = {}
    
    gpt_ips = analysis.get('ip_analysis', {}).get('originating_ips', [])
    if ip_check:
        for ip in gpt_ips:
            ip_info[ip] = lookup_ip(ip, api_key)
            blacklist_check[ip] = check_blacklist(ip, api_key)

    phishing_result = phishing_detection(body_parts)

    report = generate_report_with_findings(analysis)

    show_analysis = click.confirm("Do you want to see both the analysis and the report, or just the report?", default=True)

    if show_analysis:
        display_analysis(analysis, body_analysis, ip_info, blacklist_check, phishing_result)

    print(f"\n{Fore.GREEN}Generated Report with Findings:{Style.RESET_ALL}\n")
    print(report)

    if generate_pdf:
        output_file = click.prompt("Enter the name for the PDF report", default="email_analysis_report.pdf")
        generate_pdf_report(analysis, output_file)
        click.echo(f"{Fore.GREEN}PDF report generated as '{output_file}'{Style.RESET_ALL}")


def main_menu():
    click.clear()
    click.echo(f"{Fore.GREEN}Email Analysis Tool{Style.RESET_ALL}")
    click.echo("1. Analyze Email")
    click.echo("2. Set/Update API Keys")
    click.echo("3. Exit")
    choice = click.prompt("Enter your choice", type=int, default=1)
    return choice


@click.command()
def cli():
    global api_key, openai_api_key
    while True:
        choice = main_menu()
        if choice == 1:
            if not api_key or not openai_api_key:
                click.echo(f"{Fore.YELLOW}API keys not set. Please set them first.{Style.RESET_ALL}")
                set_api_keys()
            file_path = select_file()
            ip_check = click.confirm("Do you want to check IP against blacklists?", default=True)
            generate_pdf = click.confirm("Do you want to generate a PDF report?", default=False)
            
            # Run the email analysis
            headers, body = process_file(file_path)
            analysis = analyze_headers(headers)
            body_analysis = analyze_body(body)
            phishing_result = phishing_detection(body)

            ip_info = {}
            blacklist_check = {}
            if ip_check:
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', headers)
                for ip in ips:
                    ip_info[ip] = lookup_ip(ip, api_key)
                    blacklist_check[ip] = check_blacklist(ip, api_key)
            
            # Generate the report from GPT's response
            report = generate_report_with_findings(analysis)

            # Provide a menu for the user to choose the output
            while True:
                click.echo(f"\n{Fore.GREEN}What would you like to see?{Style.RESET_ALL}")
                click.echo("1. Analysis")
                click.echo("2. Report")
                click.echo("3. Both")
                display_choice = click.prompt("Enter your choice", type=int, default=3)

                if display_choice == 1:
                    display_analysis(analysis, body_analysis, ip_info, blacklist_check, phishing_result)
                    break
                elif display_choice == 2:
                    display_report(report)
                    break
                elif display_choice == 3:
                    display_analysis(analysis, body_analysis, ip_info, blacklist_check, phishing_result)
                    display_report(report)
                    break
                else:
                    click.echo(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

            if generate_pdf:
                output_filename = file_path.rsplit('.', 1)[0] + '_analysis_report.pdf'
                generate_pdf_report({**analysis, 'body_analysis': body_analysis, 'phishing_result': phishing_result}, output_filename)
                click.echo(f"\n{Fore.GREEN}PDF report generated: {output_filename}{Style.RESET_ALL}")
            
            click.pause()
        elif choice == 2:
            set_api_keys()
        elif choice == 3:
            click.echo("Exiting...")
            break
        else:
            click.echo(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

if __name__ == '__main__':
    cli()
