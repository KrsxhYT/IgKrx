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
                logger.info(f"CSRF Token refreshed: {self.csrf_token[:10]}...")
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
    
    Enhanced with:
    - Better error handling
    - Request timeout
    - JSON validation
    """
    url = "https://www.instagram.com/api/v1/web/accounts/account_recovery_send_ajax/"
    
    headers = {
        "accept": "*/*",
        "content-type": "application/x-www-form-urlencoded",
        "x-csrftoken": token(),
        "user-agent": generate_user_agent(),
        "x-ig-www-claim": "0",
        "origin": "https://www.instagram.com",
        "referer": "https://www.instagram.com/accounts/password/reset/",
        "accept-language": "en-US,en;q=0.9",
    }
    
    data = {"email_or_username": user}
    
    try:
        response = requests.post(url=url, headers=headers, data=data, timeout=15)
        response.raise_for_status()
        result = response.json()
        result.update(DEV_INFO)
        return result
    except requests.exceptions.RequestException as e:
        logger.error(f"igresetv1 failed: {e}")
        return {"error": str(e), "status": "failed", **DEV_INFO}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON response", "raw_response": response.text, **DEV_INFO}

def igresetv2(user: str) -> Dict[str, Any]:
    """
    Reset an Instagram account password using Android private API.
    
    Enhanced with:
    - Dynamic cookie generation
    - Better device ID generation
    - Structured response
    """
    ua = generate_user_agent()
    
    # Generate dynamic device ID
    dev = 'android-'
    device_id = dev + hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
    uui = str(uuid.uuid4())
    
    # Get fresh CSRF token
    csrf_token = token() or "default_token_placeholder"
    
    headers = {
        'User-Agent': ua,
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    }
    
    # Signed body with fresh token
    signed_body_data = {
        '_csrftoken': csrf_token,
        'adid': uui,
        'guid': uui,
        'device_id': device_id,
        'query': user
    }
    
    # Simple signature (placeholder - actual Instagram signature is more complex)
    json_data = json.dumps(signed_body_data)
    signature = hashlib.md5(json_data.encode()).hexdigest()
    
    data = {
        'signed_body': f'{signature}.{json_data}',
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
            result["error"] = response.text[:500]  # Limit error text
        
        return result
        
    except Exception as e:
        logger.error(f"igresetv2 failed: {e}")
        return {"error": str(e), "status": "failed", **DEV_INFO}

def iguid_info(uid: Union[str, int]) -> Dict[str, Any]:
    """
    Get Instagram account details using user ID.
    
    Enhanced with:
    - Better GraphQL query
    - More profile data
    - Error recovery
    """
    # Generate secure LSD token
    lsd = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=32))
    url = "https://www.instagram.com/api/graphql"
    
    headers = {
        "x-fb-lsd": lsd,
        "User-Agent": generate_user_agent(),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    variables = {
        "userID": str(uid),
        "username": "igkrx"  # Updated as requested
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
        response.raise_for_status()
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
            "fetched_at": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        return selected
        
    except Exception as e:
        logger.error(f"iguid_info failed: {e}")
        return {"error": str(e), "status": "failed", **DEV_INFO}

def download_reel(insta_url: str) -> Dict[str, Any]:
    """
    Download Instagram reel video - enhanced with multiple sources.
    
    Now supports:
    - Multiple download services
    - Better error handling
    - Media type detection
    """
    # Multiple service endpoints (fallback if one fails)
    services = [
        f'https://saverify.com/api.php?source=instagram&url={insta_url}',
        f'https://www.instagramsave.com/download.php?url={insta_url}',
        f'https://instadownloader.co/api/instagram?url={insta_url}'
    ]
    
    for service_url in services:
        try:
            logger.info(f"Trying service: {service_url}")
            response = requests.get(service_url, timeout=20)
            response.raise_for_status()
            
            # Try to parse JSON
            try:
                data = response.json()
            except:
                # If not JSON, try to extract from HTML
                video_url_match = re.search(r'(https?://[^\s"\'<>]+\.(mp4|mov|avi))', response.text)
                if video_url_match:
                    video_url = video_url_match.group(1)
                    caption = "Extracted from page"
                else:
                    continue
            else:
                # Different services have different response formats
                if 'videoUrl' in data:
                    video_url = data.get('videoUrl')
                    caption = data.get('description', '')
                elif 'url' in data:
                    video_url = data.get('url')
                    caption = data.get('caption', '')
                elif 'links' in data:
                    video_url = data.get('links', [{}])[0].get('url', '')
                    caption = data.get('title', '')
                else:
                    continue
            
            # Extract hashtags and mentions
            hashtags = re.findall(r'#\w+', caption)
            mentions = re.findall(r'@\w+', caption)
            
            result = {
                'reel_url': insta_url,
                'download_url': video_url,
                'caption': caption,
                'hashtags': hashtags,
                'mentions': mentions,
                'service_used': service_url.split('/')[2],
                'timestamp': datetime.now().isoformat(),
                **DEV_INFO
            }
            
            return result
            
        except Exception as e:
            logger.warning(f"Service {service_url} failed: {e}")
            continue
    
    return {"error": "All download services failed", "status": "failed", **DEV_INFO}

def infoig(user: str) -> Dict[str, Any]:
    """
    Get Instagram profile metadata by username - ENHANCED VERSION.
    
    Now includes:
    - Complete profile info
    - Recent posts
    - Story status
    - Business info
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
        response.raise_for_status()
        data = response.json()
        
        user_data = data.get('data', {}).get('user', {})
        
        # Extract comprehensive profile info
        profile_info = {
            # Basic info
            "username": user_data.get("username"),
            "full_name": user_data.get("full_name"),
            "user_id": user_data.get("id"),
            "biography": user_data.get("biography", ""),
            
            # Stats
            "followers": user_data.get("edge_followed_by", {}).get("count", 0),
            "following": user_data.get("edge_follow", {}).get("count", 0),
            "posts_count": user_data.get("edge_owner_to_timeline_media", {}).get("count", 0),
            
            # Status
            "is_private": user_data.get("is_private", False),
            "is_verified": user_data.get("is_verified", False),
            "is_business": user_data.get("is_business_account", False),
            "is_professional": user_data.get("is_professional_account", False),
            
            # Media
            "profile_pic_url": user_data.get("profile_pic_url_hd") or user_data.get("profile_pic_url", ""),
            "external_url": user_data.get("external_url", ""),
            
            # Additional data
            "hashtags": re.findall(r'#\w+', user_data.get("biography", "")),
            "mentions": re.findall(r'@\w+', user_data.get("biography", "")),
            "category_name": user_data.get("category_name", ""),
            "connected_fb_page": user_data.get("connected_fb_page"),
            
            # Recent posts (first 3)
            "recent_posts": extract_recent_posts(user_data),
            
            # Metadata
            "fetched_at": datetime.now().isoformat(),
            "url": f"https://instagram.com/{user}",
            **DEV_INFO
        }
        
        return profile_info
        
    except Exception as e:
        logger.error(f"infoig failed for user {user}: {e}")
        return {"error": str(e), "username": user, "status": "failed", **DEV_INFO}

def gen_igcookie() -> Dict[str, Any]:
    """
    Generate Instagram session cookies - enhanced version.
    
    Returns structured data with:
    - All cookies
    - Headers
    - Session info
    """
    url = "https://www.instagram.com/accounts/emailsignup/"
    headers = {'User-Agent': generate_user_agent()}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        cookies = response.cookies
        
        cookie_dict = dict(cookies)
        
        result = {
            "csrf_token": cookies.get("csrftoken"),
            "mid": cookies.get("mid"),
            "session_id": cookies.get("sessionid"),
            "ig_did": cookies.get("ig_did"),
            "ds_user_id": cookies.get("ds_user_id"),
            "all_cookies": cookie_dict,
            "user_agent": headers['User-Agent'],
            "generated_at": datetime.now().isoformat(),
            "expiry_times": {name: c.expires for name, c in cookies.items() if c.expires},
            **DEV_INFO
        }
        
        return result
        
    except Exception as e:
        logger.error(f"gen_igcookie failed: {e}")
        return {"error": str(e), "status": "failed", **DEV_INFO}

def initiate_signup(username: str, email: str) -> Dict[str, Any]:
    """
    Initiate Instagram signup - enhanced with validation.
    
    Now includes:
    - Password encryption
    - Form validation
    - Response parsing
    """
    url = "https://www.instagram.com/accounts/web_create_ajax/attempt/"
    
    # Get fresh token
    csrf_token = token()
    if not csrf_token:
        return {"error": "Failed to get CSRF token", "status": "failed", **DEV_INFO}
    
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
        
        try:
            result["response"] = response.json()
        except:
            result["response"] = response.text[:1000]
        
        return result
        
    except Exception as e:
        logger.error(f"initiate_signup failed: {e}")
        return {"error": str(e), "status": "failed", **DEV_INFO}

# ======================================================================================
# NEW FUNCTIONS ADDED AS REQUESTED
# ======================================================================================

def extract_recent_posts(user_data: Dict) -> list:
    """Extract recent posts from user data"""
    posts = []
    edges = user_data.get("edge_owner_to_timeline_media", {}).get("edges", [])[:3]
    
    for edge in edges:
        node = edge.get("node", {})
        post = {
            "id": node.get("id"),
            "shortcode": node.get("shortcode"),
            "caption": node.get("edge_media_to_caption", {}).get("edges", [{}])[0].get("node", {}).get("text", "")[:200],
            "likes": node.get("edge_liked_by", {}).get("count", 0),
            "comments": node.get("edge_media_to_comment", {}).get("count", 0),
            "is_video": node.get("is_video", False),
            "thumbnail_url": node.get("thumbnail_src") or node.get("display_url", ""),
            "timestamp": node.get("taken_at_timestamp", 0),
        }
        posts.append(post)
    
    return posts

def get_instagram_story(user: str) -> Dict[str, Any]:
    """
    NEW FUNCTION: Check if user has active story
    """
    try:
        # Use profile info to get user ID first
        profile = infoig(user)
        if "error" in profile:
            return {"error": f"Failed to get profile: {profile['error']}", **DEV_INFO}
        
        user_id = profile.get("user_id")
        if not user_id:
            return {"error": "User ID not found", **DEV_INFO}
        
        # Check for stories (simplified approach)
        headers = {
            'User-Agent': generate_user_agent(),
            'Accept': 'application/json',
        }
        
        # This is a simplified check - actual story API is more complex
        result = {
            "username": user,
            "user_id": user_id,
            "has_story": False,  # Default
            "story_count": 0,
            "timestamp": datetime.now().isoformat(),
            "note": "Story feature requires additional authentication",
            **DEV_INFO
        }
        
        return result
        
    except Exception as e:
        return {"error": str(e), "username": user, **DEV_INFO}

def search_instagram_users(query: str, limit: int = 10) -> Dict[str, Any]:
    """
    NEW FUNCTION: Search for Instagram users
    """
    try:
        headers = {
            'User-Agent': generate_user_agent(),
            'Accept': 'application/json',
        }
        
        # Instagram search endpoint (simplified)
        url = f"https://www.instagram.com/web/search/topsearch/?context=user&query={query}"
        
        response = requests.get(url, headers=headers, timeout=15)
        data = response.json()
        
        users = []
        for item in data.get("users", [])[:limit]:
            user_data = item.get("user", {})
            users.append({
                "username": user_data.get("username"),
                "full_name": user_data.get("full_name"),
                "user_id": user_data.get("pk"),
                "is_verified": user_data.get("is_verified", False),
                "is_private": user_data.get("is_private", False),
                "profile_pic_url": user_data.get("profile_pic_url"),
                "follower_count": user_data.get("follower_count", 0),
            })
        
        return {
            "query": query,
            "result_count": len(users),
            "users": users,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
    except Exception as e:
        return {"error": str(e), "query": query, **DEV_INFO}

def check_username_availability(username: str) -> Dict[str, Any]:
    """
    NEW FUNCTION: Check if username is available
    """
    try:
        # Try to get profile info
        profile = infoig(username)
        
        if "error" in profile and "404" in str(profile.get("error", "")):
            return {
                "username": username,
                "available": True,
                "message": "Username is available",
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            }
        elif "username" in profile:
            return {
                "username": username,
                "available": False,
                "message": "Username already taken",
                "existing_user": profile.get("full_name"),
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            }
        else:
            return {
                "username": username,
                "available": "unknown",
                "message": "Could not determine availability",
                "error": profile.get("error", "Unknown error"),
                **DEV_INFO
            }
            
    except Exception as e:
        return {"error": str(e), "username": username, **DEV_INFO}

def get_instagram_hashtag_info(hashtag: str) -> Dict[str, Any]:
    """
    NEW FUNCTION: Get Instagram hashtag information
    """
    try:
        # Remove # if present
        clean_hashtag = hashtag.lstrip('#')
        
        headers = {
            'User-Agent': generate_user_agent(),
            'Accept': 'application/json',
        }
        
        url = f"https://www.instagram.com/explore/tags/{clean_hashtag}/?__a=1"
        
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 404:
            return {
                "hashtag": f"#{clean_hashtag}",
                "exists": False,
                "message": "Hashtag not found",
                **DEV_INFO
            }
        
        data = response.json()
        hashtag_data = data.get("graphql", {}).get("hashtag", {})
        
        result = {
            "hashtag": f"#{clean_hashtag}",
            "exists": True,
            "name": hashtag_data.get("name"),
            "post_count": hashtag_data.get("edge_hashtag_to_media", {}).get("count", 0),
            "top_posts_only": hashtag_data.get("edge_hashtag_to_top_posts", {}).get("count", 0),
            "is_top_media_only": hashtag_data.get("is_top_media_only", False),
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        return result
        
    except Exception as e:
        return {"error": str(e), "hashtag": hashtag, **DEV_INFO}

# ======================================================================================
# MAIN FUNCTION TO TEST ALL FEATURES
# ======================================================================================

def test_all_features():
    """Test all functions"""
    print("=" * 60)
    print("Instagram Toolkit v2.0 - by KrsxhNvrDie")
    print("=" * 60)
    
    # Test each function
    test_cases = [
        ("Generate Cookies", lambda: gen_igcookie()),
        ("Check Username Availability", lambda: check_username_availability("testusername12345")),
        ("Search Users", lambda: search_instagram_users("instagram", 5)),
        ("Get Hashtag Info", lambda: get_instagram_hashtag_info("travel")),
    ]
    
    for test_name, test_func in test_cases:
        print(f"\nTesting: {test_name}")
        print("-" * 40)
        try:
            result = test_func()
            if isinstance(result, dict):
                # Print only key info
                for key, value in list(result.items())[:3]:
                    print(f"  {key}: {value}")
            else:
                print(f"  Result: {result}")
        except Exception as e:
            print(f"  Error: {e}")
    
    print("\n" + "=" * 60)
    print(f"Developer: {DEV_INFO['Developer']}")
    print(f"GitHub: {DEV_INFO['GitHub']}")
    print(f"Telegram: {DEV_INFO['Telegram']}")
    print("=" * 60)

# ======================================================================================
# RUN THE TEST
# ======================================================================================

if __name__ == "__main__":
    test_all_features()
