import os
import sys
import logging
import random
import time
import smtplib
import socket
import imaplib
from itertools import product

import dns.resolver
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import openai
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, ElementClickInterceptedException, NoSuchElementException
import pyfiglet
from time import sleep

# Initialize Colorama
init(autoreset=True)

# Configure Logging
logging.basicConfig(
    filename='dmarc_tool.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Set your OpenAI API key
openai.api_key = ""  # Replace with your actual OpenAI API key

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

# Dictionary of homoglyphs for generating domain variants
HOMOGLYPHS = {
    'a': ['а', 'ą'],
    'b': ['Ь', 'б'],
    'c': ['с', 'ç', 'ć', 'č'],
    'd': ['ԁ', 'd'],
    'e': ['е', 'ę'],
    'h': ['н'],
    'i': ['і', 'í', 'î', 'ï', 'į'],
    'j': ['ј'],
    'k': ['κ', 'к'],
    'l': ['l', '1',],
    'm': ['м'],
    'n': ['η', 'ń', ],
    'o': ['о', 'ò', 'ó', 'ø'],
    'p': ['р'],
    's': ['ѕ', 'ś'],
    't': ['τ', 'ť'],
    'v': ['ν'],
    'w': ['ω'],
    'x': ['х'],
    'y': ['у', 'ý', 'ÿ'],
    'z': ['ż', 'ź', 'ž'],
    'A': ['А'],
    'B': ['В'],
    'E': ['Е'],
    'H': ['Н'],
    'K': ['К'],
    'M': ['М'],
    'O': ['О'],
    'P': ['Р'],
    'T': ['Т'],
    'X': ['Х'],
    'Y': ['Ү'],
    '0': ['о'],
    '1': ['l', 'I'],
    '5': ['S'],
    '8': ['B']
}

def clear_screen():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_banner():
    """Display the tool banner using pyfiglet."""
    mx = pyfiglet.figlet_format("mx", font="colossal")
    flex = pyfiglet.figlet_format("flex", font="colossal")
    mx_lines = mx.splitlines()
    flex_lines = flex.splitlines()
    
    # Combine and print each line with appropriate colors
    for mx_line, flex_line in zip(mx_lines, flex_lines):
        print(f"{Fore.RED}{mx_line}{Fore.WHITE}{flex_line}")
    
    print(Fore.WHITE + "  [+] An all round email tool by D8RH8R [+]")

def main_menu():
    """Display the main menu and handle user input."""
    while True:
        clear_screen()
        display_banner()
        print(Fore.CYAN + "=====================================")
        print(Fore.CYAN + " What colour hat do you wear today?  ")
        print(Fore.CYAN + "=====================================")
        print(Fore.GREEN + "1. Whitehat")
        print(Fore.GREEN + "2. Blackhat")
        print(Fore.RED + "3. Exit")
        choice = input(Fore.YELLOW + "Enter your choice: ")

        if choice == '1':
            blueteam_menu()
        elif choice == '2':
            redteam_menu()
        elif choice == '3':
            print(Fore.RED + "Exiting program.")
            sys.exit()
        else:
            print(Fore.RED + "Invalid choice. Please enter a number between 1 and 3.")
            input(Fore.YELLOW + "Press Enter to continue...")

def blueteam_menu():
    """Display the Blueteam menu and handle user input."""
    while True:
        clear_screen()
        display_banner()
        print(Fore.CYAN + "========== Blueteam Menu ==========")
        print(Fore.GREEN + "1. Analyze Domain Records")
        print(Fore.GREEN + "2. SPF Record Management")
        print(Fore.GREEN + "3. DKIM Key Generation and Configuration")
        print(Fore.GREEN + "4. DMARC Policy Setup and Management")
        print(Fore.GREEN + "5. Automated Testing and Validation")
        print(Fore.GREEN + "6. Monitoring and Reporting")
        print(Fore.GREEN + "7. Automated Analysis")
        print(Fore.BLUE + "8. Back to Main Menu")
        print(Fore.RED + "9. Exit")
        choice = input(Fore.YELLOW + "Enter your choice: ")

        if choice == '1':
            analyze_domain_records()
        elif choice == '2':
            spf_record_management()
        elif choice == '3':
            dkim_key_generation()
        elif choice == '4':
            dmarc_policy_setup()
        elif choice == '5':
            automated_testing()
        elif choice == '6':
            monitoring_reporting()
        elif choice == '7':
            automated_analysis()
        elif choice == '8':
            return  # Go back to main menu
        elif choice == '9':
            print(Fore.RED + "Exiting program.")
            sys.exit()
        else:
            print(Fore.RED + "Invalid choice. Please enter a number between 1 and 9.")
            input(Fore.YELLOW + "Press Enter to continue...")

def redteam_menu():
    """Display the Redteam menu and handle user input."""
    while True:
        clear_screen()
        display_banner()
        print(Fore.CYAN + "========== Redteam Menu ==========")
        print(Fore.GREEN + "1. Generate Homoglyph Domains")
        print(Fore.GREEN + "2. Generate IP Logger Link")
        print(Fore.GREEN + "3. Generate Pretexting Messages")
        print(Fore.GREEN + "4. Banner Grabbing (SMTP)")
        print(Fore.GREEN + "5. Banner Grabbing (POP3)")
        print(Fore.GREEN + "6. Enumerate SMTP Users (VRFY Command)")
        print(Fore.GREEN + "7. Enumerate SMTP Users (RCPT TO Command)")
        print(Fore.GREEN + "8. Brute-force SMTP Authentication")
        print(Fore.BLUE + "9. Back to Main Menu")
        print(Fore.RED + "10. Exit")
        choice = input(Fore.YELLOW + "Enter your choice: ")

        if choice == '1':
            generate_homoglyph_domains()
        elif choice == '2':
            grabify_ip_link()
        elif choice == '3':
            generate_pretext_message_cli()
        elif choice == '4':
            banner_grabbing_smtp_menu()
        elif choice == '5':
            banner_grabbing_pop3_menu()
        elif choice == '6':
            smtp_enum_vrfy_menu()
        elif choice == '7':
            smtp_enum_rcpt_menu()
        elif choice == '8':
            brute_force_smtp_menu()
        elif choice == '9':
            return  # Go back to main menu
        elif choice == '10':
            print(Fore.RED + "Exiting program.")
            sys.exit()
        else:
            print(Fore.RED + "Invalid choice. Please enter a number between 1 and 5.")
            input(Fore.YELLOW + "Press Enter to continue...")

def generate_pretext_message_cli():
    """Generate pretext messages for social engineering engagements."""
    print("Select a pretext scenario:")
    print("1. Technical Support")
    print("2. Urgent Request")
    print("3. Helpdesk Inquiry")
    print("4. Software Update")
    print("5. Account Verification")
    print("6. Company Announcement")
    print("7. External Service")
    choice = input("Enter your choice (1-7): ")
    

    if choice == '1':
        scenario = "technical_support"
    elif choice == '2':
        scenario = "urgent_request"
    elif choice == '3':
        scenario = "helpdesk_inquiry"
    elif choice == '4':
        scenario = "software_update"
    elif choice == '5':
        scenario = "account_verification"
    elif choice == '6':
        scenario = "company_announcement"
    elif choice == '7':
        scenario = "external_service"
    else:
        print("Invalid choice. Returning to Redteam Menu.")
        return

    generate_pretext_message(scenario)

def generate_pretext_message(scenario):
    """Generate a pretext message based on the given scenario type and refine it using OpenAI."""
    
    # Define different pretext scenarios
    pretext_templates = {
        "technical_support": [
            "Hello {name},\n\nThis is {support_name} from IT Support. We have detected some unusual activity on your account, and we need you to verify your identity. Please reply with your username and last login time.\n\nThank you,\nIT Support",
            "Dear {name},\n\nOur records show that your account password will expire soon. To avoid any disruption, please click the link below and update your credentials.\n\n{link}\n\nBest regards,\nTechnical Support Team",
            "Hi {name},\n\nWe're performing a security audit and need to verify your account details. Please confirm your current role and department by replying to this email.\n\nThanks,\nIT Security Team",
            "Dear {name},\n\nWe've noticed multiple failed login attempts on your account. To secure your account, please click the link below to enable two-factor authentication:\n\n{link}\n\nSecurity Operations Center"
        ],
        "urgent_request": [
            "Hi {name},\n\nThis is {exec_name}, the CEO. I need you to process an urgent payment of {amount} to {recipient} immediately. Please prioritize this task and confirm once done.\n\nRegards,\n{exec_name}",
            "Dear {name},\n\nI hope you are doing well. I'm currently in a meeting and need a copy of our latest financial report. Can you please send it to my personal email urgently?\n\nBest,\n{exec_name}",
            "Hello {name},\n\nThis is {exec_name} from Legal. We need immediate access to all files related to Project X. Please send the access credentials to my private email ASAP.\n\nThank you,\n{exec_name}",
            "Hi {name},\n\nI'm {exec_name} from HR. We need to update our employee database urgently. Please fill out this form with your personal details: {link}\n\nBest regards,\n{exec_name}"
        ],
        "helpdesk_inquiry": [
            "Hello {name},\n\nWe have received a request to reset your email password. If you did not make this request, please let us know immediately. Otherwise, click the link below to reset your password:\n\n{link}\n\nBest,\nHelpdesk Team",
            "Hi {name},\n\nThis is a reminder to update your security questions in our system. Click here to complete this action: {link}\n\nBest regards,\nSupport Desk",
            "Dear {name},\n\nOur system indicates that your antivirus software is outdated. Please download and install the latest version from this link: {link}\n\nIT Helpdesk",
            "Hello {name},\n\nWe're upgrading our VPN service. To ensure continued access, please update your VPN client using this installer: {link}\n\nThanks,\nNetwork Support"
        ],
        "software_update": [
            "Dear {name},\n\nAn important security update is available for your work laptop. Please download and install it immediately from: {link}\n\nIT Department",
            "Hello {name},\n\nWe've released a critical patch for our company software. Update now to avoid disruptions: {link}\n\nSoftware Support Team"
        ],
        "account_verification": [
            "Hi {name},\n\nWe've noticed some unusual login activity. To protect your account, please verify your identity here: {link}\n\nAccount Security Team",
            "Dear {name},\n\nYour account requires reverification. Click here to confirm your details: {link}\n\nCompliance Department"
        ],
        "company_announcement": [
            "All Employees,\n\nPlease review and acknowledge our updated privacy policy by following this link: {link}\n\nHuman Resources",
            "Team,\n\nWe're conducting an employee satisfaction survey. Your input is valuable. Participate here: {link}\n\nManagement"
        ],
        "external_service": [
            "Dear {name},\n\nYour cloud storage is almost full. Upgrade your plan now to avoid service interruption: {link}\n\nCloud Storage Provider",
            "Hello {name},\n\nYour subscription to our online tools is expiring. Renew now at a discounted rate: {link}\n\nBusiness Tools Support"
        ]
}

    # Define lists of names, amounts, recipients, and links for randomization
    names = ["John", "Alice", "Michael", "Sarah"]
    support_names = ["Bob", "Emily", "Kevin", "Sandra"]
    exec_names = ["David Miller", "Jane Doe", "Robert Smith"]
    amounts = ["$5,000", "$10,000", "$15,000"]
    recipients = ["XYZ Corp", "ABC Ltd.", "MNO Inc."]
    links = ["http://changethis.com", "http://changethis-reset-password.com", "http://change-this-secure-login.com"]

    # Validate scenario input
    if scenario not in pretext_templates:
        print(f"Invalid scenario: {scenario}. Please choose from: {', '.join(pretext_templates.keys())}")
        return

    # Select a random template and replace placeholders with random values
    template = random.choice(pretext_templates[scenario])
    message = template.format(
        name=random.choice(names),
        support_name=random.choice(support_names),
        exec_name=random.choice(exec_names),
        amount=random.choice(amounts),
        recipient=random.choice(recipients),
        link=random.choice(links)
    )

    print("\nGenerated Pretext Message:\n")
    print(message)
    print(" ")
    print("[+] Refining....")
    sleep(3)
    
    # Send the message to OpenAI for refinement
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an assistant specializing in human language and the nuance of corporate communication."},
                {"role": "user", "content": f"Rewrite the following message to be more human, completelty convincing yet still professional:\n\n{message}"}
            ],
            max_tokens=350,
            temperature=0.9
        )

        # Extract and print the refined message
        clear_screen()
        display_banner()
        refined_message = response.choices[0].message.content.strip()
        print("\nRefined Pretext Message:\n")
        print(Fore.GREEN + refined_message)
        print("\n\nDon't forget to change the url!")
        save_choice = input(Fore.YELLOW + "\nWould you like to save this message to a file? (y/n): ").strip().lower()

        if save_choice == 'y':
            # Prompt the user for the file name
            file_name = input(Fore.YELLOW + "Enter the file name to save the message (e.g., message.txt): ").strip()
            
            # Save the refined message to the specified file
            try:
                with open(file_name, 'w') as file:
                    file.write(refined_message)
                print(Fore.GREEN + f"Message successfully saved to {file_name}")
            except Exception as e:
                print(Fore.RED + f"An error occurred while saving the file: {e}")

    

    except Exception as e:
        print(Fore.RED + f"An error occurred while communicating with OpenAI: {e}")

    input(Fore.YELLOW + "Press Enter to return to the Redteam menu...")

def generate_homoglyph_domains():
    """Generate homoglyph versions of a domain and optionally provide explanations and Google dork queries."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Generate Homoglyph Domains")
    print(Fore.CYAN + "--------------------------")

    

    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")

    if '.' not in domain:
        print(Fore.RED + "Invalid domain format. Please try again.")
        return

    # Extract the domain name and TLD
    domain_name, tld = domain.rsplit('.', 1)

    homoglyph_domains = set()

    while len(homoglyph_domains) < 10:
        new_domain = list(domain_name)
        for i in range(len(new_domain)):
            char = new_domain[i]
            if char in HOMOGLYPHS:
                new_domain[i] = random.choice(HOMOGLYPHS[char])
        homoglyph_domains.add(''.join(new_domain) + '.' + tld)

    # Display generated domains
    print(Fore.GREEN + "\nGenerated Homoglyph Domains:\n")
    for i, homoglyph_domain in enumerate(homoglyph_domains, 1):
        print(Fore.YELLOW + f"{i}. {homoglyph_domain}")

    # Ask if user wants explanations or Google dork
    show_explanations = input(Fore.YELLOW + "\nWould you like to see explanations of character differences? (y/n): ").lower() == 'y'
    show_google_dork = input(Fore.YELLOW + "Would you like to generate a Google Dork query? (y/n): ").lower() == 'y'

    if show_explanations:
        print(Fore.CYAN + "\nExplanation of Character Differences:\n")
        for homoglyph_domain in homoglyph_domains:
            differences = []
            for original_char, homoglyph_char in zip(domain_name, homoglyph_domain.split('.')[0]):
                if original_char != homoglyph_char:
                    differences.append((original_char, homoglyph_char))
            diff_explanation = ', '.join([f"'{orig}' -> '{homo}'" for orig, homo in differences])
            print(Fore.YELLOW + f"{homoglyph_domain}: " + "\n" + Fore.LIGHTBLACK_EX + diff_explanation)

    if show_google_dork:
        print(Fore.CYAN + "\nGoogle Dork Query to Search for Homoglyph Domains Online:\n")
        google_dork = ' OR '.join([f'site:{homoglyph_domain}' for homoglyph_domain in homoglyph_domains])
        print(Fore.YELLOW + google_dork)

    input(Fore.YELLOW + "\nPress Enter to return to the Main Menu...")

    # Initialize colorama for Windows
    init(autoreset=True)

def grabify_ip_link():
    def ip_logger(driver_path, target_url, username, password):
        # Set up ChromeDriver with Service
        service = Service(driver_path)
        
        # Initialize the WebDriver (e.g., Chrome) with the Service object
        driver = webdriver.Chrome(service=service)
        
        def safe_find_element(driver, by, value, timeout=10):
            try:
                return WebDriverWait(driver, timeout).until(
                    EC.presence_of_element_located((by, value))
                )
            except TimeoutException:
                print(f"Element not found: {by}={value}")
                return None
        
        def click_button_safely(driver, button):
            try:
                button.click()
            except ElementClickInterceptedException:
                driver.execute_script("arguments[0].scrollIntoView(true);", button)
                time.sleep(1)
                driver.execute_script("arguments[0].click();", button)
        
        try:
            # Open Grabify login page
            driver.get('https://grabify.link/login')
            print("Current URL after navigating to login page:", driver.current_url)
        
            # Enter username and password
            username_field = safe_find_element(driver, By.ID, 'username-or-email')
            password_field = safe_find_element(driver, By.ID, 'password')
            
            if username_field and password_field:
                username_field.send_keys(username)
                password_field.send_keys(password)
                print("Username and password entered")
            else:
                print("Failed to find username or password field")
        
            # Click the login button
            login_button = safe_find_element(driver, By.XPATH, '//button[@class="button is-primary" and @type="submit"]')
            if login_button:
                click_button_safely(driver, login_button)
                print("Login button clicked")
            else:
                print("Failed to find login button")
        
            print("Current URL after attempting login:", driver.current_url)
        
            # Wait for login to complete and navigate to the main page
            try:
                WebDriverWait(driver, 10).until(EC.url_contains('grabify.link'))
                print("Successfully logged in")
            except TimeoutException:
                print("Login might have failed or took too long")
        
            # Open Grabify's main page to create a shortened URL
            driver.get('https://grabify.link/')
            print("Current URL after navigating to the main page:", driver.current_url)
        
            # Find and fill the URL input field
            url_input = safe_find_element(driver, By.ID, 'linkToShorten')
            if url_input:
                url_input.send_keys(target_url)
                print("Target URL entered")
            else:
                print("Failed to find URL input field")
        
            # Find and click the submit button
            submit_button = safe_find_element(driver, By.ID, 'create')
            if submit_button:
                click_button_safely(driver, submit_button)
                print("Submit button clicked")
            else:
                print("Failed to find submit button")
        
            # Wait for the result URL to appear
            result_url = safe_find_element(driver, By.XPATH, '//input[@id="result-url"]')
            if result_url:
                print(f'Generated Grabify URL: {result_url.get_attribute("value")}')
            else:
                print("Failed to find result URL")
        
            # Wait for the table to load
            table = safe_find_element(driver, By.CLASS_NAME, 'table-responsive')
            if table:
                print("Table found, attempting to extract content")
                soup = BeautifulSoup(driver.page_source, 'html.parser')
                table_content = soup.find('table')
                if table_content:
                    print("Table content:")
                    for row in table_content.find_all('tr'):
                        cells = row.find_all(['td', 'th'])
                        row_text = ""
                        for i, cell in enumerate(cells):
                            cell_text = cell.get_text(strip=True)
                            if i == 0:
                                # First column - bold blue
                                row_text += Fore.BLUE + Style.BRIGHT + cell_text + Style.RESET_ALL
                            elif i == 1:
                                # Second column - bold white
                                row_text += " | " + Fore.WHITE + Style.BRIGHT + cell_text + Style.RESET_ALL
                            else:
                                # Remaining columns - default color
                                row_text += " | " + cell_text
                        print(row_text)
                else:
                    print("No table content found in the page source")
            else:
                print("Failed to find table element")
        
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")
            print("Current page source:")
            print(driver.page_source)
        
        finally:
            # Close the WebDriver
            driver.quit()

    # Example of how to call the function
    driver_path = r"C:\Users\d8rh8r\Downloads\chromedriver-win64 (1)\chromedriver-win64\chromedriver.exe"
    target_url = input("Please enter the URL you want to shorten with Grabify: ")
    username = input("Please enter your Grabify username: ")
    password = input("Please enter your Grabify password: ")

    clear_screen()
    display_banner()
    print(Fore.WHITE + "[+] You must have an account at grabify.link for \nthis tool to function. ")
    ip_logger(driver_path, target_url, username, password)
    input(Fore.YELLOW + "[+] Press Enter to continue...")

def banner_grabbing_smtp_menu():
    """Menu for Banner Grabbing (SMTP)"""
    clear_screen()
    display_banner()
    print("\n[INFO] Banner Grabbing (SMTP)")
    print("[DESCRIPTION] Banner grabbing involves connecting to the SMTP server to retrieve the initial response. \nThis response often contains information about the server software, \nversion, and other details useful for further enumeration.")
    
    ip = input(Fore.YELLOW + "\nEnter target IP for SMTP Banner Grabbing: ")
    port = int(input(Fore.YELLOW + "Enter SMTP port (default is 25): ") or 25)
    banner_grabbing_smtp(Fore.BLUE + ip, port)

def banner_grabbing_smtp(ip, port=25):
    """Banner Grabbing for SMTP Server"""
    try:
        with socket.create_connection((ip, port), timeout=10) as s:
            banner = s.recv(1024)
            print(f"[RESULT] SMTP Banner: {banner.decode().strip()}")
    except Exception as e:
        print(f"[ERROR] Error grabbing banner from {ip}:{port} - {e}")

def banner_grabbing_pop3_menu():
    """Menu for Banner Grabbing (POP3)"""
    clear_screen()
    display_banner()
    print("\n[INFO] Banner Grabbing (POP3)")
    print("[DESCRIPTION] Banner grabbing involves connecting to the POP3 server to retrieve the initial response. This response often contains information about the server software, version, and other details useful for further enumeration.")
    
    ip = input("\nEnter target IP for POP3 Banner Grabbing: ")
    port = int(input("Enter POP3 port (default is 110): ") or 110)
    banner_grabbing_pop3(ip, port)

def banner_grabbing_pop3(ip, port=110):
    """Banner Grabbing for POP3 Server"""
    try:
        with socket.create_connection((ip, port), timeout=10) as s:
            banner = s.recv(1024)
            print(f"[RESULT] POP3 Banner: {banner.decode().strip()}")
            input("Press a key to continue")
    except Exception as e:
        print(f"[ERROR] Error grabbing banner from {ip}:{port} - {e}")

def smtp_enum_vrfy_menu():
    """Menu for Enumerating SMTP Users (VRFY Command)"""
    clear_screen()
    display_banner()
    print("\n[INFO] Enumerate SMTP Users using VRFY Command")
    print("[DESCRIPTION] The VRFY command is used to verify if a particular email address is valid on the SMTP server. It can help identify valid usernames on the target system.")
    
    ip = input("\nEnter target IP for SMTP User Enumeration (VRFY): ")
    user_list = input("Enter comma-separated user list (e.g., admin,test,user): ").split(',')
    smtp_enum_vrfy(ip, user_list)

def smtp_enum_vrfy(ip, user_list):
    """Enumerate SMTP Users using VRFY Command"""
    try:
        server = smtplib.SMTP(ip)
        server.set_debuglevel(0)
        for user in user_list:
            try:
                code, message = server.verify(user)
                print(f"[RESULT] VRFY {user}: {message}")
            except smtplib.SMTPResponseException as e:
                print(f"[INFO] VRFY {user}: {e.smtp_error.decode()}")
        server.quit()
    except Exception as e:
        print(f"[ERROR] Error enumerating SMTP users - {e}")

def smtp_enum_rcpt_menu():
    """Menu for Enumerating SMTP Users (RCPT TO Command)"""
    clear_screen()
    display_banner()
    print("\n[INFO] Enumerate SMTP Users using RCPT TO Command")
    print("[DESCRIPTION] The RCPT TO command checks the validity of recipient email addresses. It is used after MAIL FROM in SMTP transactions to identify valid email addresses.")
    
    ip = input("\nEnter target IP for SMTP User Enumeration (RCPT TO): ")
    from_email = input("Enter a valid sender email (e.g., attacker@example.com): ")
    user_list = input("Enter comma-separated user list (e.g., admin,test,user): ").split(',')
    smtp_enum_rcpt(ip, from_email, user_list)

def smtp_enum_rcpt(ip, from_email, user_list):
    """Enumerate SMTP Users using RCPT TO Command"""
    try:
        server = smtplib.SMTP(ip)
        server.mail(from_email)
        for user in user_list:
            try:
                code, message = server.rcpt(user)
                print(f"[RESULT] RCPT TO {user}: {message}")
            except smtplib.SMTPResponseException as e:
                print(f"[INFO] RCPT TO {user}: {e.smtp_error.decode()}")
        server.quit()
    except Exception as e:
        print(f"[ERROR] Error enumerating SMTP users with RCPT TO - {e}")

def brute_force_smtp_menu():
    """Menu for Brute-forcing SMTP Authentication"""
    clear_screen()
    display_banner()
    print("\n[INFO] Brute-force SMTP Authentication")
    print("[DESCRIPTION] Brute force attempts to authenticate against the SMTP server using a list of usernames and passwords.")
    
    ip = input("\nEnter target IP for SMTP Brute-forcing: ")
    port = int(input("Enter SMTP port (default is 25): ") or 25)
    user_list = input("Enter comma-separated user list (e.g., admin,test,user): ").split(',')
    password_list = input("Enter comma-separated password list (e.g., password,admin123,test123): ").split(',')
    brute_force_smtp(ip, port, user_list, password_list)

def brute_force_smtp(ip, port, user_list, password_list):
    """Brute-force SMTP authentication"""
    for user, password in product(user_list, password_list):
        try:
            server = smtplib.SMTP(ip, port)
            server.starttls()
            server.login(user, password)
            print(f"[RESULT] Login successful with {user}:{password}")
            server.quit()
            break
        except smtplib.SMTPAuthenticationError:
            print(f"[INFO] Login failed for {user}:{password}")
        except Exception as e:
            print(f"[ERROR] Error during brute force: {e}")
            break



def spf_record_management():
    """Handle SPF Record Management tasks."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "SPF Record Management")
    print(Fore.CYAN + "---------------------")
    print(Fore.GREEN + "1. Generate SPF Record")
    print(Fore.GREEN + "2. Validate SPF Record")
    print(Fore.GREEN + "3. Optimize SPF Record")
    print(Fore.RED + "4. Back to Main Menu")
    choice = input(Fore.YELLOW + "Enter your choice: ")

    if choice == '1':
        generate_spf_record()
    elif choice == '2':
        validate_spf_record()
    elif choice == '3':
        optimize_spf_record()
    elif choice == '4':
        return
    else:
        print(Fore.RED + "Invalid choice. Please enter a number between 1 and 4.")
        input(Fore.YELLOW + "Press Enter to continue...")
        spf_record_management()

def analyze_domain_records():
    """Analyze a domain's SPF, DKIM, and DMARC records for errors or problems."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Analyze Domain Records")
    print(Fore.CYAN + "----------------------")
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")

    results = {'domain': domain, 'spf': None, 'dkim': [], 'dmarc': None}

    try:
        # Analyze SPF Record
        print(Fore.CYAN + "\nAnalyzing SPF Record...")
        spf_record = None
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if 'v=spf1' in str(rdata):
                    spf_record = str(rdata).replace('"', '')
                    print(Fore.GREEN + f"SPF record found: {spf_record}")
                    results['spf'] = spf_record
                    break
            if not spf_record:
                print(Fore.RED + "No SPF record found.")
                logging.warning(f"No SPF record found for {domain}.")
        except dns.resolver.NoAnswer:
            print(Fore.RED + "No SPF record found for this domain.")
            logging.warning(f"No SPF record found for {domain}.")
        
        # Analyze DKIM Records
        print(Fore.CYAN + "\nAnalyzing DKIM Records...")
        selectors = ['default', 'google', 'selector1', 'selector2']
        for selector in selectors:
            try:
                answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                for rdata in answers:
                    print(Fore.GREEN + f"DKIM record found for selector '{selector}': {rdata}")
                    results['dkim'].append((selector, str(rdata)))
                    logging.info(f"DKIM record found for selector '{selector}' for {domain}: {rdata}")
            except dns.resolver.NoAnswer:
                print(Fore.RED + f"No DKIM record found for selector '{selector}'.")
                logging.warning(f"No DKIM record found for selector '{selector}' for {domain}.")
            except Exception as e:
                print(Fore.RED + f"Error occurred while checking DKIM record for selector '{selector}': {e}")
                logging.error(f"Error occurred while checking DKIM record for selector '{selector}' for {domain}: {e}")

        # Analyze DMARC Record
        print(Fore.CYAN + "\nAnalyzing DMARC Record...")
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in answers:
                print(Fore.GREEN + f"DMARC record found: {rdata}")
                results['dmarc'] = str(rdata)
                logging.info(f"DMARC record found for {domain}: {rdata}")
        except dns.resolver.NoAnswer:
            print(Fore.RED + "No DMARC record found for this domain.")
            logging.warning(f"No DMARC record found for {domain}.")
        except Exception as e:
            print(Fore.RED + f"Error occurred while checking DMARC record: {e}")
            logging.error(f"Error occurred while checking DMARC record for {domain}: {e}")

    except Exception as e:
        print(Fore.RED + f"Error occurred while analyzing domain records: {e}")
        logging.error(f"Error occurred while analyzing domain records for {domain}: {e}")

    input(Fore.YELLOW + "Press Enter to continue...")
    return results  # Ensure results are returned properly

def submit_to_chatgpt():
    """
    Perform domain analysis and submit results to ChatGPT for a comprehensive report.
    """
    # Include the domain analysis code directly here
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")

    results = {'domain': domain, 'spf': None, 'dkim': [], 'dmarc': None}

    try:
        # Analyze SPF Record
        print(Fore.CYAN + "\nAnalyzing SPF Record...")
        spf_record = None
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if 'v=spf1' in str(rdata):
                    spf_record = str(rdata).replace('"', '')
                    print(Fore.GREEN + f"SPF record found: {spf_record}")
                    results['spf'] = spf_record
                    break
            if not spf_record:
                print(Fore.RED + "No SPF record found.")
                logging.warning(f"No SPF record found for {domain}.")
        except dns.resolver.NoAnswer:
            print(Fore.RED + "No SPF record found for this domain.")
            logging.warning(f"No SPF record found for {domain}.")
        
        # Analyze DKIM Records
        print(Fore.CYAN + "\nAnalyzing DKIM Records...")
        selectors = ['default', 'google', 'selector1', 'selector2']
        for selector in selectors:
            try:
                answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                for rdata in answers:
                    print(Fore.GREEN + f"DKIM record found for selector '{selector}': {rdata}")
                    results['dkim'].append((selector, str(rdata)))
                    logging.info(f"DKIM record found for selector '{selector}' for {domain}: {rdata}")
            except dns.resolver.NoAnswer:
                print(Fore.RED + f"No DKIM record found for selector '{selector}'.")
                logging.warning(f"No DKIM record found for selector '{selector}' for {domain}.")
            except Exception as e:
                print(Fore.RED + f"Error occurred while checking DKIM record for selector '{selector}': {e}")
                logging.error(f"Error occurred while checking DKIM record for selector '{selector}' for {domain}: {e}")

        # Analyze DMARC Record
        print(Fore.CYAN + "\nAnalyzing DMARC Record...")
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in answers:
                print(Fore.GREEN + f"DMARC record found: {rdata}")
                results['dmarc'] = str(rdata)
                logging.info(f"DMARC record found for {domain}: {rdata}")
        except dns.resolver.NoAnswer:
            print(Fore.RED + "No DMARC record found for this domain.")
            logging.warning(f"No DMARC record found for {domain}.")
        except Exception as e:
            print(Fore.RED + f"Error occurred while checking DMARC record: {e}")
            logging.error(f"Error occurred while checking DMARC record for {domain}: {e}")

    except Exception as e:
        print(Fore.RED + f"Error occurred while analyzing domain records: {e}")
        logging.error(f"Error occurred while analyzing domain records for {domain}: {e}")

    # Proceed with ChatGPT submission only if there are valid records
    if results['spf'] or results['dkim'] or results['dmarc']:
        print(Fore.CYAN + "\nSubmitting analysis results to ChatGPT for a comprehensive report...")

        # Prepare the prompt based on analysis results
        prompt = f"""
        You are a cybersecurity expert. Analyze the following domain's email authentication records for SPF, DKIM, and DMARC. Provide your analysis in the following structured format with specific headings:

        1. SPF Record:
        Provide details of the SPF record found, if any. Explain the significance and whether it is correctly configured.

        2. DKIM Records:
        List each DKIM selector found and provide the corresponding public key record. Explain what each DKIM record means and whether it is properly configured.

        3. DMARC Record:
        Describe the DMARC record if present, its policy (none, quarantine, reject), and its impact on email delivery and security.

        4. Security Status:
        Provide a summary of the overall security posture of the domain based on the SPF, DKIM, and DMARC records. Indicate whether the domain is "Secure" or "Insecure."

        5. Mitigation for Potential Issues:
        Offer any recommendations or steps to improve the email security posture based on the findings.

        Domain: {results['domain']}

        SPF Record:
        {results['spf']}

        DKIM Records:
        {', '.join([f"Selector: {sel}, Record: {rec}" for sel, rec in results['dkim']])}

        DMARC Record:
        {results['dmarc']}

        Provide a report on the health, security, and suggested mitigations for any issues found. Include comprehensive step-by-step instructions.
        """

        try:
            # Call OpenAI's ChatGPT API
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert."},
                    {"role": "user", "content": prompt}
                ]
            )

            # Extract and format the response for colorization
            analysis_report = response['choices'][0]['message']['content']
            print(Fore.GREEN + "\nChatGPT Report on Domain Analysis:\n")
            colorize_chatgpt_response(analysis_report)

            logging.info("ChatGPT analysis and report generated.")

            # Prompt to save to a file or return to the main menu
            print(Fore.YELLOW + "\nWhat would you like to do next?")
            print(Fore.YELLOW + "1. Save the report to a file")
            print(Fore.YELLOW + "2. Return to the main menu")
            choice = input(Fore.YELLOW + "Enter your choice: ")

            if choice == '1':
                save_report_to_file(analysis_report)
            elif choice == '2':
                return
            else:
                print(Fore.RED + "Invalid choice. Returning to main menu.")
                input(Fore.YELLOW + "Press Enter to continue...")
        except Exception as e:
            print(Fore.RED + f"Error occurred while communicating with ChatGPT: {e}")
            logging.error(f"Error occurred while communicating with ChatGPT: {e}")
    else:
        print(Fore.RED + "No valid records to analyze. Please check the domain and try again.")

def colorize_chatgpt_response(response):
    """
    Colorize the response from ChatGPT for better readability with headings, results, and security status.
    """
    # Split the response into lines
    lines = response.split('\n')

    for line in lines:
        stripped_line = line.strip()
        
        # Detect lines that start with a number followed by a period (e.g., "1. ", "2. ")
        if stripped_line.startswith(tuple(f"{i}." for i in range(1, 10))):
            print(Style.BRIGHT + Fore.WHITE + stripped_line)  # White and bold for numbered headings
        elif "Security Status:" in stripped_line:
            # Print the Security Status heading in bold white
            print(Style.BRIGHT + Fore.WHITE + stripped_line)
        elif "Secure" in stripped_line:
            # Print positive security status in green
            print(Fore.LIGHTGREEN_EX + stripped_line)
        elif any(word in stripped_line for word in ["Insecure", "Warning", "Error", "Fail", "Vulnerable"]):
            # Print any negative or warning status in red
            print(Fore.RED + stripped_line)
        elif any(keyword in stripped_line for keyword in ["Advice:", "Recommendation:", "Mitigation:"]):
            # Print subheadings like advice or recommendations in cyan
            print(Fore.CYAN + stripped_line)
        else:
            # General text in light grey for readability
            print(Fore.LIGHTBLACK_EX + stripped_line)

def save_report_to_file(report):
    """
    Save the ChatGPT report to a file.
    """
    file_name = input(Fore.YELLOW + "Enter the filename to save the report (e.g., report.txt): ")
    try:
        with open(file_name, 'w') as file:
            file.write(report)
        print(Fore.GREEN + f"Report saved successfully to {file_name}")
        logging.info(f"Report saved to {file_name}")
    except Exception as e:
        print(Fore.RED + f"Error saving the report to file: {e}")
        logging.error(f"Error saving the report to file: {e}")

def automated_analysis():
    """Perform automated analysis by analyzing domain records and submitting to ChatGPT."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Automated Analysis")
    print(Fore.CYAN + "------------------")
    submit_to_chatgpt()
    input(Fore.YELLOW + "Press Enter to return to Main Menu...")


def generate_spf_record():
    """Generate SPF Record based on user input."""
    clear_screen()
    print(Fore.CYAN + "Generate SPF Record")
    print(Fore.CYAN + "------------------")
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")
    email_providers = input(Fore.YELLOW + "Enter your email providers (comma-separated, e.g., _spf.google.com, _spf.example.com): ")
    ip_addresses = input(Fore.YELLOW + "Enter additional IP addresses allowed to send email (comma-separated, e.g., 192.168.1.1): ")

    spf_record = f"v=spf1 include:{email_providers} ip4:{ip_addresses} ~all"
    print(Fore.GREEN + f"Generated SPF Record for {domain}:")
    print(Fore.GREEN + spf_record)

    logging.info(f"Generated SPF Record for {domain}: {spf_record}")
    input(Fore.YELLOW + "Press Enter to return to SPF Record Management...")

def validate_spf_record():
    """Validate SPF Record using DNS queries."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Validate SPF Record")
    print(Fore.CYAN + "-------------------")
    domain = input(Fore.YELLOW + "Enter your domain name to validate SPF (e.g., example.com): ")

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf1' in str(rdata):
                print(Fore.GREEN + f"SPF record found: {rdata}")
                logging.info(f"Validated SPF Record for {domain}: {rdata}")
    except dns.resolver.NoAnswer:
        print(Fore.RED + "No SPF record found for this domain.")
    except Exception as e:
        print(Fore.RED + f"Error occurred while validating SPF record: {e}")
        logging.error(f"Error occurred while validating SPF record for {domain}: {e}")

    input(Fore.YELLOW + "Press Enter to return to SPF Record Management...")

def optimize_spf_record():
    """Optimize SPF Record to avoid exceeding DNS lookup limit."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Optimize SPF Record")
    print(Fore.CYAN + "-------------------")
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")

    try:
        # Fetch SPF records
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        for rdata in answers:
            if 'v=spf1' in str(rdata):
                spf_record = str(rdata).replace('"', '')
                break

        if spf_record:
            print(Fore.GREEN + f"Current SPF Record: {spf_record}")
            # Count DNS lookups in SPF record
            dns_lookups = spf_record.count('include:') + spf_record.count('a') + spf_record.count('mx') + spf_record.count('ptr')
            print(Fore.GREEN + f"Number of DNS Lookups: {dns_lookups}")

            if dns_lookups > 10:
                print(Fore.RED + "Warning: SPF record exceeds the 10 DNS lookup limit. Consider the following optimizations:")
                # Suggestions for optimization
                print(Fore.YELLOW + "1. Minimize the number of 'include' mechanisms.")
                print(Fore.YELLOW + "2. Use 'ip4' and 'ip6' mechanisms instead of 'include' where possible.")
                print(Fore.YELLOW + "3. Remove any redundant mechanisms.")
            else:
                print(Fore.GREEN + "SPF Record is within the 10 DNS lookup limit.")

            logging.info(f"Optimized SPF Record for {domain}. DNS Lookups: {dns_lookups}")
        else:
            print(Fore.RED + "No SPF record found for this domain.")
    except dns.resolver.NoAnswer:
        print(Fore.RED + "No SPF record found for this domain.")
    except Exception as e:
        print(Fore.RED + f"Error occurred while optimizing SPF record: {e}")
        logging.error(f"Error occurred while optimizing SPF record for {domain}: {e}")

    input(Fore.YELLOW + "Press Enter to return to SPF Record Management...")

def dkim_key_generation():
    """Handle DKIM Key Generation and Configuration tasks."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "DKIM Key Generation and Configuration")
    print(Fore.CYAN + "-------------------------------------")
    print(Fore.GREEN + "1. Generate DKIM Key Pair")
    print(Fore.GREEN + "2. Manage DKIM Selectors")
    print(Fore.GREEN + "3. Check DKIM Configuration")
    print(Fore.RED + "4. Back to Main Menu")
    choice = input(Fore.YELLOW + "Enter your choice: ")

    if choice == '1':
        generate_dkim_key_pair()
    elif choice == '2':
        manage_dkim_selectors()
    elif choice == '3':
        check_dkim_configuration()
    elif choice == '4':
        return
    else:
        print(Fore.RED + "Invalid choice. Please enter a number between 1 and 4.")
        input(Fore.YELLOW + "Press Enter to continue...")
        dkim_key_generation()

def generate_dkim_key_pair():
    """Generate a DKIM Key Pair."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Generate DKIM Key Pair")
    print(Fore.CYAN + "----------------------")
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")
    selector = input(Fore.YELLOW + "Enter DKIM selector (e.g., default): ")

    print(Fore.GREEN + "Generating DKIM Key Pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{selector}_private_key.pem", "wb") as f:
        f.write(private_key_pem)

    with open(f"{selector}_public_key.pem", "wb") as f:
        f.write(public_key_pem)

    print(Fore.GREEN + f"DKIM Key Pair generated for {domain} with selector {selector}.")
    print(Fore.GREEN + f"Private key saved to {selector}_private_key.pem")
    print(Fore.GREEN + f"Public key saved to {selector}_public_key.pem")

    logging.info(f"DKIM Key Pair generated for {domain} with selector {selector}.")

    input(Fore.YELLOW + "Press Enter to return to DKIM Configuration...")

def manage_dkim_selectors():
    """Manage DKIM Selectors."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Manage DKIM Selectors")
    print(Fore.CYAN + "---------------------")
    print(Fore.YELLOW + "Feature coming soon.")
    input(Fore.YELLOW + "Press Enter to return to DKIM Configuration...")

def check_dkim_configuration():
    """Check DKIM Configuration on the mail server."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Check DKIM Configuration")
    print(Fore.CYAN + "------------------------")
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")
    selector = input(Fore.YELLOW + "Enter DKIM selector (e.g., default): ")

    try:
        answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
        for rdata in answers:
            print(Fore.GREEN + f"DKIM record found: {rdata}")
            logging.info(f"Checked DKIM Configuration for {domain} with selector {selector}: {rdata}")
    except dns.resolver.NoAnswer:
        print(Fore.RED + "No DKIM record found for this domain and selector.")
        logging.warning(f"No DKIM record found for {domain} with selector {selector}.")
    except Exception as e:
        print(Fore.RED + f"Error occurred while checking DKIM configuration: {e}")
        logging.error(f"Error occurred while checking DKIM configuration for {domain} with selector {selector}: {e}")

    input(Fore.YELLOW + "Press Enter to return to DKIM Configuration...")

def dmarc_policy_setup():
    """Handle DMARC Policy Setup and Management tasks."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "DMARC Policy Setup and Management")
    print(Fore.CYAN + "---------------------------------")
    print(Fore.GREEN + "1. Generate DMARC Record")
    print(Fore.GREEN + "2. Update DMARC Record")
    print(Fore.GREEN + "3. DMARC Policy Advisor")
    print(Fore.RED + "4. Back to Main Menu")
    choice = input(Fore.YELLOW + "Enter your choice: ")

    if choice == '1':
        generate_dmarc_record()
    elif choice == '2':
        update_dmarc_record()
    elif choice == '3':
        dmarc_policy_advisor()
    elif choice == '4':
        return
    else:
        print(Fore.RED + "Invalid choice. Please enter a number between 1 and 4.")
        input(Fore.YELLOW + "Press Enter to continue...")
        dmarc_policy_setup()

def generate_dmarc_record():
    """Generate a DMARC Record based on user input."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Generate DMARC Record")
    print(Fore.CYAN + "---------------------")
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")
    policy = input(Fore.YELLOW + "Enter DMARC policy (none, quarantine, reject): ")
    rua = input(Fore.YELLOW + "Enter aggregate report email (e.g., dmarc-reports@example.com): ")

    dmarc_record = f"v=DMARC1; p={policy}; rua=mailto:{rua}"
    print(Fore.GREEN + f"Generated DMARC Record for {domain}:")
    print(Fore.GREEN + dmarc_record)

    logging.info(f"Generated DMARC Record for {domain}: {dmarc_record}")
    input(Fore.YELLOW + "Press Enter to return to DMARC Policy Setup...")

def update_dmarc_record():
    """Update existing DMARC Record."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Update DMARC Record")
    print(Fore.CYAN + "-------------------")
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")
    new_policy = input(Fore.YELLOW + "Enter new DMARC policy (none, quarantine, reject): ")

    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            existing_record = str(rdata)
            print(Fore.GREEN + f"Existing DMARC record: {existing_record}")

            updated_record = existing_record.replace(f"p={existing_record.split(';')[1].split('=')[1].strip()}", f"p={new_policy}")
            print(Fore.GREEN + f"Updated DMARC record: {updated_record}")

            logging.info(f"Updated DMARC Record for {domain}: {updated_record}")
    except dns.resolver.NoAnswer:
        print(Fore.RED + "No DMARC record found for this domain.")
        logging.warning(f"No DMARC record found for {domain}.")
    except Exception as e:
        print(Fore.RED + f"Error occurred while updating DMARC record: {e}")
        logging.error(f"Error occurred while updating DMARC record for {domain}: {e}")

    input(Fore.YELLOW + "Press Enter to return to DMARC Policy Setup...")

def dmarc_policy_advisor():
    """Advise on DMARC Policy based on existing setup."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "DMARC Policy Advisor")
    print(Fore.CYAN + "--------------------")
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")

    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            print(Fore.GREEN + f"Current DMARC record: {rdata}")
            if 'p=none' in str(rdata):
                print(Fore.YELLOW + "Advisory: Consider moving from 'none' to 'quarantine' or 'reject' after monitoring.")
            elif 'p=quarantine' in str(rdata):
                print(Fore.YELLOW + "Advisory: Consider moving to 'reject' if no legitimate emails are being quarantined.")
            else:
                print(Fore.YELLOW + "Advisory: Your DMARC policy is set to 'reject', which provides the highest level of protection.")
            
            logging.info(f"Advisory provided for DMARC policy for {domain}.")
    except dns.resolver.NoAnswer:
        print(Fore.RED + "No DMARC record found for this domain.")
        logging.warning(f"No DMARC record found for {domain}.")
    except Exception as e:
        print(Fore.RED + f"Error occurred while advising DMARC policy: {e}")
        logging.error(f"Error occurred while advising DMARC policy for {domain}: {e}")

    input(Fore.YELLOW + "Press Enter to return to DMARC Policy Setup...")

def analyze_domain_records():
    """Analyze a domain's SPF, DKIM, and DMARC records for errors or problems."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Analyze Domain Records")
    print(Fore.CYAN + "----------------------")
    domain = input(Fore.YELLOW + "Enter your domain name (e.g., example.com): ")

    try:
        # Analyze SPF Record
        print(Fore.CYAN + "\nAnalyzing SPF Record...")
        spf_record = None
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                if 'v=spf1' in str(rdata):
                    spf_record = str(rdata).replace('"', '')
                    print(Fore.GREEN + f"SPF record found: {spf_record}")
                    break
            if not spf_record:
                print(Fore.RED + "No SPF record found.")
                logging.warning(f"No SPF record found for {domain}.")
        except dns.resolver.NoAnswer:
            print(Fore.RED + "No SPF record found for this domain.")
            logging.warning(f"No SPF record found for {domain}.")
        
        # Analyze DKIM Records
        print(Fore.CYAN + "\nAnalyzing DKIM Records...")
        selectors = ['default', 'google', 'selector1', 'selector2']
        for selector in selectors:
            try:
                answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                for rdata in answers:
                    print(Fore.GREEN + f"DKIM record found for selector '{selector}': {rdata}")
                    logging.info(f"DKIM record found for selector '{selector}' for {domain}: {rdata}")
            except dns.resolver.NoAnswer:
                print(Fore.RED + f"No DKIM record found for selector '{selector}'.")
                logging.warning(f"No DKIM record found for selector '{selector}' for {domain}.")
            except Exception as e:
                print(Fore.RED + f"Error occurred while checking DKIM record for selector '{selector}': {e}")
                logging.error(f"Error occurred while checking DKIM record for selector '{selector}' for {domain}: {e}")

        # Analyze DMARC Record
        print(Fore.CYAN + "\nAnalyzing DMARC Record...")
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in answers:
                print(Fore.GREEN + f"DMARC record found: {rdata}")
                logging.info(f"DMARC record found for {domain}: {rdata}")
        except dns.resolver.NoAnswer:
            print(Fore.RED + "No DMARC record found for this domain.")
            logging.warning(f"No DMARC record found for {domain}.")
        except Exception as e:
            print(Fore.RED + f"Error occurred while checking DMARC record: {e}")
            logging.error(f"Error occurred while checking DMARC record for {domain}: {e}")

    except Exception as e:
        print(Fore.RED + f"Error occurred while analyzing domain records: {e}")
        logging.error(f"Error occurred while analyzing domain records for {domain}: {e}")

    input(Fore.YELLOW + "Press Enter to return to Main Menu...")

def automated_testing():
    """Handle Automated Testing and Validation tasks."""
    clear_screen()
    display_banner()
    print(Fore.CYAN + "Automated Testing and Validation")
    print(Fore.CYAN + "--------------------------------")
    print(Fore.YELLOW + "Feature coming soon.")
    input(Fore.YELLOW + "Press Enter to return to Main Menu...")

def monitoring_reporting():
    """Handle Monitoring and Reporting tasks."""
    clear_screen()
    print(Fore.CYAN + "Monitoring and Reporting")
    print(Fore.CYAN + "------------------------")
    print(Fore.YELLOW + "Feature coming soon.")
    input(Fore.YELLOW + "Press Enter to return to Main Menu...")

if __name__ == "__main__":
    main_menu()
