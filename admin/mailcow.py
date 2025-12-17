import os
import requests
from dotenv import load_dotenv
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

API_URL = os.getenv("MAILCOW_API_URL")
API_KEY = os.getenv("MAILCOW_API_KEY")

if not API_URL or not API_KEY:
    raise ValueError("MAILCOW_API_URL and MAILCOW_API_KEY must be set in .env file")

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "only.bltnm.store"
}

def create_mailbox(local_part, domain, password, name, quota=1024, active=True):
    """
    Create a new mailbox in Mailcow
    
    Args:
        local_part (str): The local part of the email (before @)
        domain (str): The domain part of the email (after @)
        password (str): The password for the mailbox
        name (str): The full name of the mailbox owner
        quota (int): Quota in MB (default: 1024)
        active (bool): Whether the mailbox is active (default: True)
    
    Returns:
        dict: API response
    """
    try:
        url = f"{API_URL}/add/mailbox"
        data = {
            "active": "1" if active else "0",
            "local_part": local_part,
            "domain": domain,
            "name": name,
            "authsource": "mailcow",
            "password": password,
            "password2": password,
            "quota": str(quota),
            "force_pw_update": "1",
            "tls_enforce_in": "1",
            "tls_enforce_out": "1",
            "tags": []
        }
        
        logger.info(f"Creating mailbox: {local_part}@{domain}")
        logger.info(f"API URL: {url}")
        logger.info(f"Headers: {HEADERS}")
        logger.info(f"Data: {data}")
        
        response = requests.post(url, headers=HEADERS, json=data, timeout=30)
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response headers: {response.headers}")
        
        # Log response content for debugging (be careful with sensitive data)
        if response.text:
            logger.info(f"Response text length: {len(response.text)}")
        
        response.raise_for_status()
        
        result = response.json()
        logger.info(f"Mailbox creation result: {result}")
        return result
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP Error creating mailbox: {str(e)}")
        logger.error(f"Response content: {response.text}")
        return {"error": f"HTTP Error: {str(e)}", "details": response.text}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating mailbox: {str(e)}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error creating mailbox: {str(e)}")
        return {"error": str(e)}

def delete_mailbox(local_part, domain):
    """
    Delete a mailbox from Mailcow
    
    Args:
        local_part (str): The local part of the email (before @)
        domain (str): The domain part of the email (after @)
    
    Returns:
        dict: API response
    """
    try:
        # Correct API endpoint for deleting mailboxes
        url = f"{API_URL}/delete/mailbox"
        # The API expects an array of email addresses to delete
        data = [f"{local_part}@{domain}"]
        
        logger.info(f"Deleting mailbox: {local_part}@{domain}")
        logger.info(f"API URL: {url}")
        logger.info(f"Headers: {HEADERS}")
        logger.info(f"Data: {data}")
        
        response = requests.post(url, headers=HEADERS, json=data, timeout=30)
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response headers: {response.headers}")
        
        response.raise_for_status()
        
        result = response.json()
        logger.info(f"Mailbox deletion result: {result}")
        return result
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP Error deleting mailbox: {str(e)}")
        logger.error(f"Response content: {response.text}")
        return {"error": f"HTTP Error: {str(e)}", "details": response.text}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error deleting mailbox: {str(e)}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error deleting mailbox: {str(e)}")
        return {"error": str(e)}

def get_mailboxes():
    """
    Get all mailboxes from Mailcow
    
    Returns:
        dict: API response with mailbox data
    """
    try:
        url = f"{API_URL}/get/mailbox/all"
        
        logger.info("Fetching all mailboxes")
        logger.info(f"API URL: {url}")
        logger.info(f"Headers: {HEADERS}")
        
        response = requests.get(url, headers=HEADERS, timeout=30)
        logger.info(f"Response status code: {response.status_code}")
        
        response.raise_for_status()
        
        result = response.json()
        logger.info(f"Fetched {len(result) if isinstance(result, list) else 'N/A'} mailboxes")
        return result
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP Error fetching mailboxes: {str(e)}")
        logger.error(f"Response content: {response.text}")
        return {"error": f"HTTP Error: {str(e)}", "details": response.text}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching mailboxes: {str(e)}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error fetching mailboxes: {str(e)}")
        return {"error": str(e)}

def get_domains():
    """
    Get all domains from Mailcow
    
    Returns:
        dict: API response with domain data
    """
    try:
        url = f"{API_URL}/get/domain/all"
        
        logger.info("Fetching all domains")
        logger.info(f"API URL: {url}")
        logger.info(f"Headers: {HEADERS}")
        
        response = requests.get(url, headers=HEADERS, timeout=30)
        logger.info(f"Response status code: {response.status_code}")
        
        response.raise_for_status()
        
        result = response.json()
        logger.info(f"Fetched {len(result) if isinstance(result, list) else 'N/A'} domains")
        return result
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP Error fetching domains: {str(e)}")
        logger.error(f"Response content: {response.text}")
        return {"error": f"HTTP Error: {str(e)}", "details": response.text}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching domains: {str(e)}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error fetching domains: {str(e)}")
        return {"error": str(e)}

def update_mailbox_quota(local_part, domain, quota):
    """
    Update mailbox quota
    
    Args:
        local_part (str): The local part of the email (before @)
        domain (str): The domain part of the email (after @)
        quota (int): New quota in MB
    
    Returns:
        dict: API response
    """
    try:
        url = f"{API_URL}/edit/mailbox"
        data = {
            "attr": {
                "quota": quota
            },
            "items": [f"{local_part}@{domain}"]
        }
        
        logger.info(f"Updating quota for mailbox: {local_part}@{domain} to {quota}MB")
        response = requests.post(url, headers=HEADERS, json=data, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        logger.info(f"Mailbox quota update result: {result}")
        return result
    except requests.exceptions.RequestException as e:
        logger.error(f"Error updating mailbox quota: {str(e)}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error updating mailbox quota: {str(e)}")
        return {"error": str(e)}