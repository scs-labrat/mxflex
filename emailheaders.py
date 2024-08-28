import email
import sys
import os
import openai
import json

# Set your OpenAI API key
openai.api_key = 'your-api-key-here'

def extract_headers(email_source):
    msg = email.message_from_string(email_source)
    headers = []
    for key, value in msg.items():
        headers.append(f"{key}: {value}")
    return "\n".join(headers)

def process_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        email_source = file.read()
    return extract_headers(email_source)

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

Provide your analysis in JSON format.
"""

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are an expert in email security and header analysis."},
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message['content']

def get_file_path():
    if len(sys.argv) > 1:
        return sys.argv[1]
    else:
        while True:
            file_path = input("Please enter the path to your .eml file: ").strip()
            if os.path.exists(file_path) and file_path.lower().endswith('.eml'):
                return file_path
            else:
                print("Invalid file path or not an .eml file. Please try again.")

def main():
    file_path = get_file_path()
    
    if os.path.exists(file_path):
        headers = process_file(file_path)
        analysis = analyze_headers(headers)
        
        # Pretty print the JSON response
        print(json.dumps(json.loads(analysis), indent=2))
    else:
        print(f"Error: File '{file_path}' not found.")

if __name__ == "__main__":
    main()