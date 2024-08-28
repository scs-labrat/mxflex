import click
import os
import email
import re
import logging
from colorama import Fore, Style, init
from dotenv import load_dotenv
import google.generativeai as genai  # Import the Google Generative AI library

# Set up logging
#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Load environment variables from .env file
load_dotenv()

# Global variable for the Gemini API key
gemini_api_key = os.getenv('GEMINI_API_KEY')  # Ensure this key is set in your environment

# Configure the Generative AI API with your API key
genai.configure(api_key=gemini_api_key)

# Initialize the Gemini model
model = genai.GenerativeModel('gemini-1.5-flash')

# Define the analysis prompt template
analysis_prompt_template = """Analyze the following email headers and perform these tasks:

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

Here is the email content for analysis:

{content}
"""

def run_gemini_prompt(prompt):
    """Run a prompt against the Gemini model and return the text content."""
    try:
        response = model.generate_content(prompt)
        #logging.debug(f"Raw response from Gemini: {response}")

        # Ensure the response is correctly structured and has the required content
        if response and hasattr(response, '_result'):
            result = response._result

            if result.candidates:
                # Extract text from content parts
                for candidate in result.candidates:
                    if candidate.content.parts:
                        for part in candidate.content.parts:
                            # Access 'text' attribute directly from the Part object
                            if hasattr(part, 'text'):
                                return part.text

        # If no valid text was found, return None
        click.echo(f"{Fore.RED}Error: No valid content found in the Gemini response. Please check the prompt and try again.{Style.RESET_ALL}")
        return None

    except AttributeError as e:
        click.echo(f"{Fore.RED}AttributeError: {str(e)}. Please check the response format or API call.{Style.RESET_ALL}")
        return None
    except Exception as e:
        click.echo(f"{Fore.RED}Error: Failed to connect to Gemini API. {str(e)}{Style.RESET_ALL}")
        return None

def process_file(file_path):
    """Read the .eml file and extract its headers and body."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        email_source = file.read()
    msg = email.message_from_string(email_source)

    headers = "\n".join([f"{key}: {value}" for key, value in msg.items()])

    body = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body.append(part.get_payload(decode=True).decode())
    else:
        body.append(msg.get_payload(decode=True).decode())

    return headers, "\n".join(body)

def colorize_output(text):
    """Apply colorization to the Gemini response output."""
    colorized_text = text
    
    # Bold green for section headings that begin with a number
    colorized_text = re.sub(r"(^\d+\..*?:)", f"{Fore.GREEN}{Style.BRIGHT}\\1{Style.RESET_ALL}", colorized_text, flags=re.MULTILINE)
    
    # Bright blue for text before a colon, white after the colon
    colorized_text = re.sub(r"(\*\*.*?\*\*):", f"{Fore.CYAN}\\1{Style.RESET_ALL}:{Fore.WHITE}", colorized_text)

    return colorized_text

def display_response(response):
    """Display Gemini's response with colorization."""
    if not response:
        click.echo(f"{Fore.RED}No response received from Gemini.{Style.RESET_ALL}")
        return

    print(f"{Fore.GREEN}Gemini Analysis Result:{Style.RESET_ALL}")
    colorized_response = colorize_output(response)
    print(colorized_response)

def set_api_keys():
    global gemini_api_key
    if not gemini_api_key:
        gemini_api_key = click.prompt("Enter your Gemini API key", type=str)

    with open('.env', 'w') as f:
        f.write(f"GEMINI_API_KEY={gemini_api_key}\n")

    click.echo(f"{Fore.GREEN}API keys have been saved to .env file.{Style.RESET_ALL}")

def select_file():
    """Prompt user to select an .eml file."""
    while True:
        file_path = click.prompt("Enter the path to your .eml file", type=click.Path(exists=True))
        if file_path.lower().endswith('.eml'):
            return file_path
        else:
            click.echo(f"{Fore.RED}Please provide a valid .eml file.{Style.RESET_ALL}")

@click.command()
def run_email_analysis():
    """Simplified email analysis using Gemini."""
    if not gemini_api_key:
        click.echo(f"{Fore.YELLOW}API key not set. Please set it first.{Style.RESET_ALL}")
        set_api_keys()

    file_path = select_file()
    headers, body = process_file(file_path)

    # Combine headers and body for submission to Gemini
    email_content = f"Headers:\n{headers}\n\nBody:\n{body}"

    # Insert the email content into the prompt
    prompt = analysis_prompt_template.format(content=email_content)

    # Send the prompt to Gemini and get response
    response = run_gemini_prompt(prompt)

    # Display the formatted response
    display_response(response)

if __name__ == '__main__':
    run_email_analysis()
