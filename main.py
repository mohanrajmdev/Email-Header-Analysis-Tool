import re, requests
import email
from colorama import *
from tqdm import *
from time import sleep
from datetime import datetime
from prettytable import *

vt_access_token = '<Your VirusTotal Api Key>'

# Extract links from the email
def extract_url(file_path):
    url_pattern = r'(https?://\S+)'

    with open(file_path) as file:
        fp = file.read()
        # Find all URLs in the email header
        urls = re.findall(url_pattern, fp)
        li = []

        # Print the URLs
        for url in urls:
            li.append(url)
        return li


# Extract ip from the email
def extract_ip(file_path):
    # Regular expression to match IP addresses
    ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
    with open(file_path) as file:
        fp = file.read()
        # Find all IP addresses in the header
        return list(set(re.findall(ip_pattern, fp)))


# sender address domain check (Weight : 20)
def check_sender_address(msg):
    try:
        email_pattern = r'<(.+@[^>]+)>'

        # Find the email address
        email = re.search(email_pattern, msg['From']).group(1)

        # Split the email address at the '@' symbol
        name, domain = email.split('@')
        score = 0
        url = "https://www.virustotal.com/api/v3/domains/" + domain
        headers = {
            "accept": "application/json",
            "x-apikey": vt_access_token
        }
        response = requests.get(url, headers=headers).json()
        r = response['data']['attributes']['last_analysis_stats']
        if (r['malicious'] > 0):
            score += 5
        else:
            score += 2.5
        if (r['suspicious'] > 0):
            score += 5
        else:
            score += 2.5

        if (r['undetected'] > 20):
            score += 5
    except:
        print("From field is Not Found.")

    return score


# Links in Email (Weight: 25)
def check_url(lst):
    count = 0
    score = 0
    print("Checking for Links ...")
    sleep(10)

    for k in tqdm(lst):
        if (k[-1] == '"' or k[-1] == "'" or k[-1] == '.' or k[-1] == '>' or k[-1] == '<'):
            k = k[:-1]

        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': f'{vt_access_token}', 'resource': k}

        # Below condition is for checking the 4 url per minute because of virustotal api constraints
        if count != 0 and count % 4 == 0:
            print(' Wait for 30 more seconds ...')
            sleep(30)
        count += 1

        try:
            response = requests.get(url, params=params)
            r = response.json()

            if r['positives'] > 0:
                pos_count = int(r['positives'])
                score += pos_count
                obj = r['scans']
                for key in obj.keys():
                    if (obj[key]['detected']):
                        name_scan = obj[key]['result'].split(" ")[0]
                        if (name_scan in ['phishing', 'malicious', 'malware']):
                            score += 1.5

        except Exception as e:
            print('\nUrl is not Detected.')
            score += 1

        sleep(10)

    if score >= 25:
        return 25
    elif score < 25 and score > 7:
        return score

    return 5


# SPF Record Check (Weight: 15)
def spf_check(msg):
    spf_pattern = r'spf=(\w{4})'
    Authentication_result = re.search(spf_pattern, msg['Authentication-Results']).group(1)
    spf_record = msg['Received-SPF'].split(" ")[0]

    score = 0
    if (Authentication_result == 'pass'):
        score = 2.5
    else:
        score = 10

    if (spf_record == 'Pass'):
        score = score + 2.5
    else:
        score = score + 5
    return score


# DKIM Check (Weight: 15)
def dkim_check(msg):
    dkim_pattern = r'dkim=(\w{4})'
    dkim_record = re.search(dkim_pattern, msg['Authentication-Results']).group(1)

    score = 0
    if (dkim_record == 'pass'):
        score = 5
    elif (dkim_record == 'none'):
        score = 10
    else:
        score = 15

    return score


# DMARC Check (Weight: 10)
def dmarc_check(msg):
    dmarc_pattern = r'dmarc=(\w{4})'
    dmarc_record = re.search(dmarc_pattern, msg['Authentication-Results']).group(1)

    score = 0
    if (dmarc_record == 'pass' or dmarc_record == 'best'):
        score = 0
    elif (dmarc_record == 'none'):
        score = 5
    else:
        score = 10

    return score


# Unusual Sending Behavior (Weight: 15)
def unusual_check(msg):
    timestamps = []
    server_cnt = 0
    for key, value in msg.items():
        if (key == 'Received'):
            server_cnt = server_cnt + 1
            time_val = value.split(' ')[-2]
            if (time_val[8:] == '\n'):
                time_val = time_val[:-1]
            if ('+' not in time_val and ':' in time_val):
                timestamps.append(time_val)
    # print(timestamps)
    score = 0

    try:

        datetime_format = "%H:%M:%S"
        datetime_objects = [datetime.strptime(ts, datetime_format) for ts in timestamps]

        # Find the time taken
        time_taken = datetime_objects[0] - datetime_objects[-1]
        hms = str(time_taken).split(":")
        hours = int(hms[0])
        minutes = int(hms[1])
        seconds = int(hms[2])

        if (server_cnt > 5):
            score = 5
        else:
            score = 2.5

        if (hours > 0 or minutes > 0):
            score += 10
        elif (seconds > 10):
            score += 5
        else:
            score += 2.5
    except:
        score = 5

    return score


# Content Analysis (Weight : 25)
def content_analysis(msg):
    score = 0

    for header, value in msg.items():
        urgent_words = ["urgent", "immediate", "action required", "deadline"]
        if any(word in value.lower() for word in urgent_words):
            # if word in present in the email score will be increased
            score += 5

        if header.lower() == "content-type" and "attachment; filename=" in value.lower():
            filename = re.findall(r'filename="(.*?)"', value.lower())[0]
            extension = filename.split(".")[-1].lower()
            suspicious_extensions = [".vbs", ".exe", ".bat", ".js", ".out", ".mal"]
            if extension in suspicious_extensions:
                score += 5

    return score


# Reply-To-Filed (Weight : 10)
def check_reply_to_sender(msg):
    # Check if the domains of sender and reply-to email addresses match
    try:
        sender_email = msg['From']
        reply_to_email = msg['Reply-To']
        sender_domain = re.search('@(.+)', sender_email).group(1)
        reply_to_domain = re.search('@(.+)', reply_to_email).group(1)
        if (sender_domain[-1] == '>'):
            sender_domain = sender_domain[:-1]
        if (reply_to_domain[-1] == '>'):
            reply_to_domain = reply_to_domain[:-1]
        # print(sender_domain , reply_to_domain)
        if (sender_domain != reply_to_domain):
            return 10
    except:
        print("No Reply To field in the email")

    return 5


# IP Reputation of Sender (Weight: 10)
def check_ip(lst):
    score = 0
    print("Checking the Ip address ....")
    sleep(1)
    for k in tqdm(lst):
        url = ("https://www.virustotal.com/api/v3/ip_addresses/%s" % k)
        headers = {
            "Accept": "application/json",
            "x-apikey": f"{vt_access_token}"
        }
        try:
            r = requests.get(url, headers=headers).json()
            dict_web = r['data']['attributes']['last_analysis_results']

            tot_detect_c = 0

            for i in dict_web:
                if dict_web[i]['category'] == "malicious" or dict_web[i]['category'] == "suspicious":
                    tot_detect_c = 1 + tot_detect_c

            if tot_detect_c >= 10:
                score = 10
            else:
                if (tot_detect_c <= 3):
                    score = 3
                else:
                    score = tot_detect_c

            sleep(1)

        except Exception as e:
            print('An error occured, Error Type:', type(e))
            print('Please Try again...')
    return score


def calculate_total_score(msg, file_path):
    score_sender_address = check_sender_address(msg)
    score_spf = spf_check(msg)
    score_dkim = dkim_check(msg)
    score_dmarc = dmarc_check(msg)
    score_unusual = unusual_check(msg)
    score_ip = check_ip(extract_ip(file_path))
    score_content = content_analysis(msg)
    score_replyto = check_reply_to_sender(msg)
    score_url = check_url(extract_url(file_path))

    # Create a PrettyTable instance
    table = PrettyTable()

    # Define table columns
    table.field_names = ["Category", "Score"]

    # Add data to the table
    table.add_row(["Sender Domain score ", score_sender_address])
    table.add_row(["Links Score ", score_url])
    table.add_row(["SPF Score ", score_spf])
    table.add_row(["DKIM Score ", score_dkim])
    table.add_row(["DMARC Score ", score_dmarc])
    table.add_row(["Content Analysis Score ", score_content])
    table.add_row(["Unusual Behaviour Score ", score_unusual])
    table.add_row(["Reply-To Score ", score_replyto])
    table.add_row(["IP Check Score ", score_ip])
    table.align["Score"]='l'
    table.align = 'c'

    print(table)

    return score_url + score_replyto + score_ip + score_unusual + score_content + score_dkim + score_dmarc + score_spf + score_sender_address


def interpret_score(total_score):
    if total_score <= 20:
        return "Likely Safe"
    elif total_score <= 40:
        print(Fore.GREEN)
        return "Low Risk"
    elif total_score <= 70:
        print(Fore.LIGHTRED_EX)
        return "Moderate Risk"
    else:
        print(Fore.RED)
        return "High Risk"


def main():
    print(Back.BLACK + Fore.RED + '''
    ░█▀▀░█▄█░█▀█░▀█▀░█░░░░░█▀█░█▀█░█▀█░█░░░█░█░▀▀█░█▀▀░█▀▄░░░▀█▀░█▀█░█▀█░█░░
    ░█▀▀░█░█░█▀█░░█░░█░░░░░█▀█░█░█░█▀█░█░░░░█░░▄▀░░█▀▀░█▀▄░░░░█░░█░█░█░█░█░░
    ░▀▀▀░▀░▀░▀░▀░▀▀▀░▀▀▀░░░▀░▀░▀░▀░▀░▀░▀▀▀░░▀░░▀▀▀░▀▀▀░▀░▀░░░░▀░░▀▀▀░▀▀▀░▀▀▀
    ''' + Fore.RESET, end="")

    print(Fore.LIGHTMAGENTA_EX + '''
    * This tool help to find email header hop list . Also help to spf and DKIM signature verification. You can check all mail is legitimate or not By the Score.
    Analyzing email headers can provide valuable information for identifying potentially malicious domains and urls.

    * This tool is used to check the Sender's Email Address,Links in this Email,SPF Record Check,DKIM Check,DMARC Check,Content Analysis,Unusual Sending Behavior,' \
    Reply-To Field,IP Reputation of Sender and its return the score of this email.
    ''' + Fore.RESET)

    print('''
    █▄█ ▄▀▄ █   █   ▀█▀ ▄▀▄   █ █ ▄▀▀ ██▀   ▀█▀ █▄█ █ ▄▀▀   ▀█▀ ▄▀▄ ▄▀▄ █     ▄▀▄
    █ █ ▀▄▀ ▀▄▀▄▀    █  ▀▄▀   ▀▄█ ▄██ █▄▄    █  █ █ █ ▄██    █  ▀▄▀ ▀▄▀ █▄▄    ▄▀
        1 . copy the path from the email header file ( .eml file extension)
            Eg : C:\\Users\\cybersecurity\\Winter-Intern\\OSINT\\samples\\sample-997.eml
        2 . Enter this path in the given input
        3 . Result will be shown for this eml file.
    ''')

    print(Fore.LIGHTGREEN_EX)

    file_path = input("Enter the file path from the root : ").strip()

    with open(file_path) as file:
        msg = email.message_from_file(file)

        file_name = file_path.split("/")[-1]
        print(f"Content of '{file_name}' : ")

        content_analysis(msg)

        # Calculate total score and interpret the result
        total_score = calculate_total_score(msg, file_path)
        interpretation = interpret_score(total_score)

        # Displaying the Result
        # Create a PrettyTable instance
        table = PrettyTable()

        # Define table columns
        table.field_names = ["Category ", "Final Score"]

        # Add data to the table
        table.add_row(["Total Score ", total_score])
        table.add_row(["Interpretation ", interpretation])
        table.align["Final Score"]='l'
        table.align = 'c'

        print(table)
        print(Fore.RESET)
        print(f"\n{'-' * 150}")
        file.close()


if __name__ == "__main__":
    main()
