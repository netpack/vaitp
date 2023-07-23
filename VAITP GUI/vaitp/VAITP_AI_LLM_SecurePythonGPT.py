'''

Script: VAITP_AI_LLM_GPT_VulnerabilityCheck.py
Author: Frédéric Bogaerts
Date: 19/07/2023
Description: From a given Python file provided as an input parameter,
             check if the given code has known vulnerabilities.
Usage: python VAITP_AI_LLM_GPT_VulnerabilityCheck.py -i input_file [-m model (gpt3.5-turbo or text-ada-002)] 

'''


import re, openai, sys, pathlib, os, json
from optparse import OptionParser


# Global variable to control debug mode
DEBUG_MODE = False

def debug_print(message):
    if DEBUG_MODE:
        print(message)


#Function to check if the given input file exists and can be opened
def file_exists(file_path):
    if os.path.exists(file_path) and os.path.isfile(file_path):
        try:
            with open(file_path):
                pass
            return True
        except IOError:
            return False
    else:
        return False


#Function to load the configuration file for model, endpoint, engine, and openai key
def load_config(config_file_path):
    if file_exists(config_file_path):
        with open(config_file_path, 'r') as file:
            config_data = json.load(file)
        return config_data
    else:
        exit("Unable to open VAITP_SecurePythonGPT.config")


#Load the config file
config_file = "../vaitp/VAITP_SecurePythonGPT.config"
config = load_config(config_file)


#parameters parsing
parser = OptionParser()
parser.add_option("-i", "--input_file", action="store", type="string", dest="vaitp_input_file", help="Set the input Python file to be scanned")
parser.add_option("-m", "--model", action="store", type="string", dest="vaitp_model", help="Set the model to use [gpt3.5-turbo or text-ada-002]")

(options, sys.argv) = parser.parse_args(sys.argv)


# Welcome message
debug_print(f"VAITP :: Starting VAITP_AI_LLM_GPT_VulnerabilityCheck.py...")


#Check if input file parameter has been provided
if not options.vaitp_input_file:
    exit("VAITP :: Please specify a file to scan with '-i file_name'.")
else:
    #Check if the extenssion of the provided file is .py
    if not options.vaitp_input_file.endswith(".py"):
        exit("VAITP :: Please provide a Python ('.py') file as input.")


#Check if the file actually extists and can be opened for reading
if file_exists(options.vaitp_input_file):
    debug_print(f"VAITP :: Loading python code from {options.vaitp_input_file}...")
    pyfile_fp = open(options.vaitp_input_file,'r')
    source = pyfile_fp.read()
else:
    exit("VAITP :: There was an error loading the provided input file. Please check.")


# Set the Azure OpenAI API endpoint and engine name
debug_print(f"VAITP :: Setting up OpenAI credentials...")

vaitp_model = config["VAITP_MODEL"]
AZURE_ENGINE_NAME = config["AZURE_ENGINE_NAME"]
AZURE_OPENAI_ENDPOINT =  config["AZURE_OPENAI_ENDPOINT"]
AZURE_OPENAI_KEY = config["AZURE_OPENAI_KEY"]

openai.api_type = "azure"
openai.api_base = AZURE_OPENAI_ENDPOINT
openai.api_version = "2023-05-15"
openai.api_key = AZURE_OPENAI_KEY

debug_print(f"VAITP :: GPT model set to {vaitp_model}")


#Function that check if a code is vulnerable
def generate_security_check(vuln):

    response = openai.ChatCompletion.create(
        engine=AZURE_ENGINE_NAME,
        messages=[
            {"role": "system", "content": "The objective is to analyze the Python code provided by the user and assess its potential security vulnerabilities. The subsequent step involves summarizing the findings using an academic approach."},
            {"role": "user", "content": vuln}
        ]
    )

    # Access the first choice in the 'choices' list
    first_choice = response['choices'][0]

    # Extract the content from the first choice's 'message' field
    content = first_choice['message']['content']

    return content


#Check with LLM and print the response
print(generate_security_check(source))


#print final message
debug_print(f"VAITP :: Thank you, come again!")