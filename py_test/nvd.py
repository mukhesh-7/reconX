import requests
import logging
import time
import os 

# Configure logging
logging.basicConfig(filename='api_key_check.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

def is_valid_api_key(apiKey, retries=3, delay=5, timeout=10):
    test_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    test_params = {'startIndex': 0, 'resultsPerPage': 1}
    headers = {'apiKey': apiKey}

    for attempt in range(retries):
        try:
            logging.info(f"Attempt {attempt + 1} to check API key.")
            test_response = requests.get(test_url, params=test_params, headers=headers, timeout=timeout)
            if test_response.status_code == 200:
                logging.info("API key is valid.")
                return True
            elif test_response.status_code == 403:
                logging.error("Forbidden: The API key might be invalid or rate-limited.")
                return False
            else:
                logging.error(f"Unexpected status code {test_response.status_code} on attempt {attempt + 1}")
        except requests.Timeout:
            logging.error(f"Request timed out on attempt {attempt + 1}")
        except requests.RequestException as e:
            logging.error(f"Request failed on attempt {attempt + 1}: {e}")
        time.sleep(delay)

    logging.error("API key validation failed after multiple attempts.")
    return False

# Replace 'your_api_key_here' with your actual API key
apiKey = os.environ.get("NVD_API_KEY")
print("NVD_API_KEY from env:", apiKey)
if is_valid_api_key(apiKey):
    print("API key is valid.")
else:
    print("Error: Invalid API key.")