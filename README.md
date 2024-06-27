# Email-Header-Analysis-Tool
[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=mohanrajmdev_Email-Header-Analysis-Tool)](https://sonarcloud.io/summary/new_code?id=mohanrajmdev_Email-Header-Analysis-Tool)

![Tool image](email-tool.png)
This tool help to find email header hop list . Also help to spf and DKIM signature verification. You can check all mail is legitimate or not By the Score. Analyzing email headers can provide valuable information for identifying potentially malicious domains and urls.

[![SonarCloud](https://sonarcloud.io/images/project_badges/sonarcloud-white.svg)](https://sonarcloud.io/summary/new_code?id=mohanrajmdev_Email-Header-Analysis-Tool)

## Phishing Detection Algorithm

![image](https://github.com/mohanrajmdev/Email-Header-Analysis-Tool/assets/97905847/f1c01e87-3a21-4e10-85a7-f208b47bbe67)
![image](https://github.com/mohanrajmdev/Email-Header-Analysis-Tool/assets/97905847/e2913846-ba2a-4b97-9e78-4b8010fccaf3)
![image](https://github.com/mohanrajmdev/Email-Header-Analysis-Tool/assets/97905847/a339f313-e362-474f-85fc-344a33e64c0d)

# Installation

## 1. Clone the repository using the following command: 

    $ git clone https://github.com/mohanrajmdev/Email-Header-Analysis-Tool.git

## 2. Navigate to the cloned directory:

    $ cd Email-Header-Analysis-Tool

# Required Packages
Command to install all packages 

    $ pip install -r requirements.txt

# Set Your Virustotal Api Key 
you will need to obtain API keys for the VirusTotal APIs. You can sign up for these services and obtain your API keys on the following websites:

* VirusTotal: https://www.virustotal.com/gui/join-us

set the Virustotal api to main.py python file
` vt_access_api = {virustotal_api_key} `

# To run the python file

    $ python3 main.py
