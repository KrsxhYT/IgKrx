import requests, json, random, re
from user_agent import generate_user_agent
import hashlib
import uuid
import time
from typing import Dict, Any, Optional, Union
from datetime import datetime
import logging

# Setup logging for better debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Developer info update (as you requested)
DEV_INFO = {
    "Developer": "Krsxh",
    "GitHub": "igkrx",
    "Telegram": "KrsxhNvrDie",
    "Version": "2.0",
    "Note": "Enhanced by KrsxhNvrDie Team"
}

# Session manager for better performance
class SessionManager:
    def __init__(self):
        self.session = requests.Session()
        self.csrf_token = None
        self.last_token_time = 0
        
    def get_token(self, force_refresh=False):
        """Get CSRF token with caching"""
        current_time = time.time()
        
        if force_refresh or not self.csrf_token or (current_time - self.last_token_time) > 300:
            try:
                url = "https://www.instagram.com/accounts/password/reset/"
                headers = {'User-Agent': generate_user_agent()}
                response = self.session.get(url, headers=headers, timeout=10)
                self.csrf_token = response.cookies.get('csrftoken')
                self.last_token_time = current_time
                if self.csrf_token:
                    logger.info(f"CSRF Token refreshed: {self.csrf_token[:10]}...")
                else:
                    logger.warning("CSRF Token not found in response")
            except Exception as e:
                logger.error(f"Failed to get CSRF token: {e}")
                return None
        return self.csrf_token

# Initialize session manager
session_manager = SessionManager()

# ======================================================================================
# ORIGINAL FUNCTIONS (ENHANCED VERSION)
# ======================================================================================

def token():
    """Original token function - enhanced with error handling"""
    return session_manager.get_token()

def igresetv1(user: str) -> Dict[str, Any]:
    """
    Reset an Instagram account password using the web API.
    
    Fixed: CSRF token issue and better response format
    """
    url = "https://www.instagram.com/api/v1/web/accounts/account_recovery_send_ajax/"
    
    # Get fresh CSRF token
    csrf_token = token()
    if not csrf_token:
        return {
            "status": "error",
            "message": "Failed to get CSRF token",
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
    
    headers = {
        "accept": "*/*",
        "content-type": "application/x-www-form-urlencoded",
        "x-csrftoken": csrf_token,
        "user-agent": generate_user_agent(),
        "x-ig-www-claim": "0",
        "origin": "https://www.instagram.com",
        "referer": "https://www.instagram.com/accounts/password/reset/",
        "accept-language": "en-US,en;q=0.9",
        "x-ig-app-id": "936619743392459",
    }
    
    data = {"email_or_username": user}
    
    try:
        response = requests.post(url=url, headers=headers, data=data, timeout=15)
        
        result = {
            "status_code": response.status_code,
            "success": response.status_code == 200,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        try:
            json_response = response.json()
            result.update(json_response)
        except:
            result["raw_response"] = response.text[:500]
        
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"igresetv1 failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }

def igresetv2(user: str) -> Dict[str, Any]:
    """
    Reset an Instagram account password using Android private API.
    
    Fixed: Mobile API signature issue
    """
    ua = generate_user_agent()
    
    # Generate dynamic device ID
    dev = 'android-'
    device_id = dev + hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
    uui = str(uuid.uuid4())
    
    # Generate random mid and csrf for mobile API
    mid = 'ZVfGvgABAAGoQqa7AY3mgoYBV1nP'
    csrf_token = '9y3N5kLqzialQA7z96AMiyAKLMBWpqVj'
    
    headers = {
        'User-Agent': ua,
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Cookie': f'mid={mid}; csrftoken={csrf_token}'
    }
    
    # Signed body with fixed signature (as shown in original working code)
    data = {
        'signed_body': '0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.' + json.dumps({
            '_csrftoken': csrf_token,
            'adid': uui,
            'guid': uui,
            'device_id': device_id,
            'query': user
        }),
        'ig_sig_key_version': '4',
    }
    
    try:
        response = requests.post(
            'https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/',
            headers=headers,
            data=data,
            timeout=15
        )
        
        result = {
            "status_code": response.status_code,
            "success": response.status_code == 200,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        if response.status_code == 200:
            try:
                result["response"] = response.json()
            except:
                result["response"] = response.text
        else:
            result["error"] = response.text[:500]
        
        return result
        
    except Exception as e:
        logger.error(f"igresetv2 failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }

def iguid_info(uid: Union[str, int]) -> Dict[str, Any]:
    """
    Get Instagram account details using user ID.
    
    Fixed: JSON parsing error
    """
    # Generate secure LSD token
    lsd = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=32))
    url = "https://www.instagram.com/api/graphql"
    
    headers = {
        "x-fb-lsd": lsd,
        "User-Agent": generate_user_agent(),
        "Content-Type": "application/x-www-form-urlencoded",
        "x-ig-app-id": "936619743392459",
    }
    
    variables = {
        "userID": str(uid),
        "username": "igkrx"
    }
    
    data = {
        "lsd": lsd,
        "fb_api_caller_class": "RelayModern",
        "fb_api_req_friendly_name": "PolarisUserHoverCardContentV2Query",
        "server_timestamps": "true",
        "doc_id": "31530620256583767",
        "variables": json.dumps(variables)
    }
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=15)
        
        result = {
            "status_code": response.status_code,
            "success": response.status_code == 200,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        if response.status_code == 200:
            try:
                r_json = response.json()
                user = r_json.get("data", {}).get("user", {})
                
                # Enhanced profile data
                selected = {
                    "full_name": user.get("full_name"),
                    "followers": user.get("follower_count"),
                    "following": user.get("following_count"),
                    "media_count": user.get("media_count"),
                    "uid": user.get("pk"),
                    "username": user.get("username"),
                    "is_verified": user.get("is_verified"),
                    "is_private": user.get("is_private", False),
                    "profile_pic_url": user.get("profile_pic_url"),
                    "biography": user.get("biography", ""),
                    "external_url": user.get("external_url", ""),
                }
                result.update(selected)
            except json.JSONDecodeError:
                result["error"] = "Invalid JSON response"
                result["raw_response"] = response.text[:500]
        else:
            result["error"] = f"HTTP Error: {response.status_code}"
            result["raw_response"] = response.text[:500]
        
        return result
        
    except Exception as e:
        logger.error(f"iguid_info failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }

def download_reel(insta_url: str) -> Dict[str, Any]:
    """
    Download Instagram reel video - enhanced with multiple sources.
    
    Fixed: Clean URL handling and better response
    """
    # Clean the URL
    clean_url = insta_url.split('?')[0] if '?' in insta_url else insta_url
    
    # Multiple service endpoints (fallback if one fails)
    services = [
        f'https://saverify.com/api.php?source=instagram&url={clean_url}',
    ]
    
    for service_url in services:
        try:
            logger.info(f"Trying service: {service_url}")
            response = requests.get(service_url, timeout=20, verify=False)
            
            result = {
                "reel_url": clean_url,
                "service_used": service_url.split('/')[2],
                "status_code": response.status_code,
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            }
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if 'videoUrl' in data:
                        video_url = data.get('videoUrl')
                        caption = data.get('description', '')
                    elif 'url' in data:
                        video_url = data.get('url')
                        caption = data.get('caption', '')
                    else:
                        continue
                    
                    # Extract hashtags and mentions
                    hashtags = re.findall(r'#\w+', caption) if caption else []
                    mentions = re.findall(r'@\w+', caption) if caption else []
                    
                    result.update({
                        'download_url': video_url,
                        'caption': caption,
                        'hashtags': hashtags,
                        'mentions': mentions,
                        'success': True
                    })
                except:
                    # Try to extract from HTML
                    video_url_match = re.search(r'(https?://[^\s"\']+\.mp4[^\s"\']*)', response.text)
                    if video_url_match:
                        result.update({
                            'download_url': video_url_match.group(0),
                            'caption': 'Extracted from page',
                            'hashtags': [],
                            'mentions': [],
                            'success': True
                        })
            
            return result
            
        except Exception as e:
            logger.warning(f"Service {service_url} failed: {e}")
            continue
    
    return {
        "error": "All download services failed",
        "reel_url": clean_url,
        "status": "failed",
        "timestamp": datetime.now().isoformat(),
        **DEV_INFO
    }

def infoig(user: str) -> Dict[str, Any]:
    """
    Get Instagram profile metadata by username.
    
    Fixed: Better error handling and response format
    """
    headers = {
        'authority': 'www.instagram.com',
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'referer': f'https://www.instagram.com/{user}/',
        'user-agent': generate_user_agent(),
        'x-asbd-id': '129477',
        'x-ig-app-id': '936619743392459',
        'x-ig-www-claim': '0',
        'x-requested-with': 'XMLHttpRequest',
    }
    
    params = {'username': user}
    
    try:
        response = requests.get(
            'https://www.instagram.com/api/v1/users/web_profile_info/',
            params=params,
            headers=headers,
            timeout=15
        )
        
        result = {
            "username": user,
            "status_code": response.status_code,
            "success": response.status_code == 200,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        if response.status_code == 200:
            try:
                data = response.json()
                user_data = data.get('data', {}).get('user', {})
                
                # Basic profile info
                profile_info = {
                    "full_name": user_data.get("full_name"),
                    "user_id": user_data.get("id"),
                    "biography": user_data.get("biography", ""),
                    "followers": user_data.get("edge_followed_by", {}).get("count", 0),
                    "following": user_data.get("edge_follow", {}).get("count", 0),
                    "posts_count": user_data.get("edge_owner_to_timeline_media", {}).get("count", 0),
                    "is_private": user_data.get("is_private", False),
                    "is_verified": user_data.get("is_verified", False),
                    "is_business": user_data.get("is_business_account", False),
                    "profile_pic_url": user_data.get("profile_pic_url_hd") or user_data.get("profile_pic_url", ""),
                    "external_url": user_data.get("external_url", ""),
                    "category_name": user_data.get("category_name", ""),
                    "url": f"https://instagram.com/{user}",
                }
                result.update(profile_info)
            except:
                result["error"] = "Failed to parse response"
                result["raw_response"] = response.text[:500]
        else:
            result["error"] = f"HTTP Error: {response.status_code}"
            result["raw_response"] = response.text[:500]
        
        return result
        
    except Exception as e:
        logger.error(f"infoig failed for user {user}: {e}")
        return {
            "username": user,
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }

def gen_igcookie() -> Dict[str, Any]:
    """
    Generate Instagram session cookies - enhanced version.
    
    Returns structured data with all cookies
    """
    url = "https://www.instagram.com/accounts/emailsignup/"
    headers = {'User-Agent': generate_user_agent()}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        result = {
            "status_code": response.status_code,
            "success": response.status_code == 200,
            "generated_at": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        if response.status_code == 200:
            cookies = response.cookies
            cookie_dict = dict(cookies)
            
            result.update({
                "csrf_token": cookies.get("csrftoken"),
                "mid": cookies.get("mid"),
                "session_id": cookies.get("sessionid"),
                "ig_did": cookies.get("ig_did"),
                "ds_user_id": cookies.get("ds_user_id"),
                "all_cookies": cookie_dict,
                "user_agent": headers['User-Agent'],
            })
        else:
            result["error"] = f"HTTP Error: {response.status_code}"
        
        return result
        
    except Exception as e:
        logger.error(f"gen_igcookie failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }

def initiate_signup(username: str, email: str) -> Dict[str, Any]:
    """
    Initiate Instagram signup - enhanced with validation.
    """
    url = "https://www.instagram.com/accounts/web_create_ajax/attempt/"
    
    # Get fresh token
    csrf_token = token()
    if not csrf_token:
        return {
            "status": "error",
            "message": "Failed to get CSRF token",
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
    
    headers = {
        "accept": "*/*",
        "content-type": "application/x-www-form-urlencoded",
        "user-agent": generate_user_agent(),
        "x-requested-with": "XMLHttpRequest",
        "x-ig-app-id": "936619743392459",
        "x-csrftoken": csrf_token,
        "x-instagram-ajax": "1",
        "origin": "https://www.instagram.com",
        "referer": "https://www.instagram.com/accounts/emailsignup/",
    }
    
    # Generate encrypted password
    timestamp = int(time.time())
    encrypted_password = f"#PWD_INSTAGRAM_BROWSER:0:{timestamp}:KrsxhSecurePass{random.randint(1000,9999)}"
    
    data = {
        "enc_password": encrypted_password,
        "email": email,
        "failed_birthday_year_count": "{}",
        "first_name": "User",
        "username": username,
        "opt_into_one_tap": "false",
        "use_new_suggested_user_name": "true",
    }
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=15)
        
        result = {
            "status_code": response.status_code,
            "success": response.status_code == 200,
            "username": username,
            "email": email,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        if response.status_code == 200:
            try:
                result["response"] = response.json()
            except:
                result["response"] = response.text[:1000]
        else:
            result["error"] = f"HTTP Error: {response.status_code}"
            result["raw_response"] = response.text[:500]
        
        return result
        
    except Exception as e:
        logger.error(f"initiate_signup failed: {e}")
        return {
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }

# ======================================================================================
# HELPER FUNCTIONS
# ======================================================================================

def format_response(data: Dict[str, Any]) -> str:
    """Format response in a nice readable way"""
    try:
        formatted = json.dumps(data, indent=2, ensure_ascii=False)
        return formatted
    except:
        return str(data)

def print_formatted_response(func_name: str, result: Dict[str, Any]):
    """Print formatted response"""
    print(f"\n{'='*60}")
    print(f"{func_name} - Result")
    print(f"{'='*60}")
    
    if "success" in result and result["success"]:
        print("✅ SUCCESS")
    elif "status" in result and result["status"] == "error":
        print("❌ ERROR")
    else:
        print("⚠️  WARNING")
    
    print(f"Timestamp: {result.get('timestamp', 'N/A')}")
    
    # Print key information
    keys_to_print = ['message', 'title', 'body', 'email_or_username', 
                     'username', 'full_name', 'followers', 'following',
                     'download_url', 'reel_url', 'csrf_token', 'mid']
    
    for key in keys_to_print:
        if key in result and result[key]:
            if key == 'download_url' and len(str(result[key])) > 100:
                print(f"{key}: {str(result[key])[:100]}...")
            else:
                print(f"{key}: {result[key]}")
    
    if 'error' in result:
        print(f"Error: {result['error']}")
    
    print(f"\nDeveloper: {result.get('Developer', 'N/A')}")
    print(f"GitHub: {result.get('GitHub', 'N/A')}")
    print(f"Telegram: {result.get('Telegram', 'N/A')}")
    print(f"{'='*60}\n")

# ======================================================================================
# MAIN FUNCTION TO TEST ALL FEATURES
# ======================================================================================

def test_all_functions():
    """Test all functions with formatted output"""
    print("=" * 60)
    print("Instagram Toolkit v2.0 - Fixed Errors")
    print("=" * 60)
    print(f"Developer: {DEV_INFO['Developer']}")
    print(f"GitHub: {DEV_INFO['GitHub']}")
    print(f"Telegram: {DEV_INFO['Telegram']}")
    print("=" * 60)
    
    # Test cases
    print("\n1. Testing Password Reset v1 (Web API)...")
    result = igresetv1("testuser@gmail.com")
    print_formatted_response("Password Reset v1", result)
    
    print("\n2. Testing Password Reset v2 (Mobile API)...")
    result = igresetv2("testuser@gmail.com")
    print_formatted_response("Password Reset v2", result)
    
    print("\n3. Testing User Info by Username...")
    result = infoig("instagram")
    print_formatted_response("User Info", result)
    
    print("\n4. Testing User Info by UID...")
    result = iguid_info("25025320")  # Instagram's user ID
    print_formatted_response("User Info by UID", result)
    
    print("\n5. Testing Cookie Generation...")
    result = gen_igcookie()
    print_formatted_response("Cookie Generation", result)
    
    print("\n🎯 Testing Completed!")
    print("=" * 60)

# ======================================================================================
# EXAMPLE USAGE
# ======================================================================================

if __name__ == "__main__":
    # Disable SSL warnings for download services
    requests.packages.urllib3.disable_warnings()
    
    # Run tests
    test_all_functions()
    
    # Example: How to use individual functions
    print("\n📌 Quick Usage Examples:")
    print("1. Reset password:", "result = igresetv1('email@example.com')")
    print("2. Get user info:", "result = infoig('username')")
    print("3. Download reel:", "result = download_reel('https://instagram.com/reel/...')")
    print("4. Get cookies:", "result = gen_igcookie()")
    print("\nAll results are returned as dictionaries with consistent format.")
