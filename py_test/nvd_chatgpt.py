import requests
import os
from colorama import Fore, Style

# url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def cve_parse():
    # Debug: print the environment variable
    print("NVD_API_KEY from env:", os.environ.get("NVD_API_KEY"))
    id = input("Enter a CVE ID: ")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}&resultsPerPage=1"
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        raise ValueError("NVD_API_KEY environment variable not set")
    h = requests.get(url, headers={
        "apiKey": api_key
        # "requestPerPage" : 1
        # "startIndex" : 0
    }) 
    cve = h.json()['vulnerabilities'][0]['cve']
    print(cve)
    
    description = cve['descriptions'][0]['value']
    print(description)
    
    baseScore = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
    score_color = Fore.RED
    if float(baseScore) < 5:
        score_color = Fore.LIGHTYELLOW_EX
    
    baseSeverity = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
    exploitScore = cve['metrics']['cvssMetricV31'][0]['exploitabilityScore']
    impactscore = cve['metrics']['cvssMetricV31'][0]['impactScore']
    print(cve['metrics']['cvssMetricV31'][0]['impactScore'])
    
    references = cve['references']
    print(len(references))
    
    ref_len = len(references)
    ref_count = 0
    url_list = []
    while ref_count < ref_len:
        ref = references[ref_count]
        url = references[ref_count]['url']
        ref_count = ref_count + 1
        print(url)
        url_list.append(url)
        break
    
    print(f"""{Fore.CYAN}CVE ID: {id}{Style.RESET_ALL}\nDescription: {description}\n{score_color}\nBaseScore: {baseScore}\n\tSeverity: {baseSeverity}\n\tExploit Score: {exploitScore}\n\tImpact Score: {impactscore}{Style.RESET_ALL}\nReferences: {url_list}""")

cve_parse()
cve_parse()
