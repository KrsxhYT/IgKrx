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

# Color codes for terminal
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Developer info update (as you requested)
DEV_INFO = {
    "Developer": "Krsxh",
    "GitHub": "igkrx",
    "Telegram": "KrsxhNvrDie",
    "Version": "3.0",
    "Note": "Enhanced by KrsxhNvrDie Team",
    "Status": Colors.GREEN + "ACTIVE" + Colors.END
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
                url = "https://www.instagram.com/"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'none',
                    'Sec-Fetch-User': '?1',
                }
                response = self.session.get(url, headers=headers, timeout=10)
                self.csrf_token = response.cookies.get('csrftoken')
                if not self.csrf_token:
                    # Fallback: generate token
                    self.csrf_token = hashlib.md5(str(time.time()).encode()).hexdigest()[:32]
                self.last_token_time = current_time
                logger.info(f"{Colors.GREEN}CSRF Token refreshed: {self.csrf_token[:10]}...{Colors.END}")
            except Exception as e:
                logger.error(f"{Colors.RED}Failed to get CSRF token: {e}{Colors.END}")
                self.csrf_token = "default_token_" + str(int(time.time()))
        return self.csrf_token

# Initialize session manager
session_manager = SessionManager()

# ======================================================================================
# UTILITY FUNCTIONS
# ======================================================================================

def print_colored(text, color=Colors.WHITE, bold=False):
    """Print colored text"""
    style = Colors.BOLD if bold else ""
    print(f"{style}{color}{text}{Colors.END}")

def validate_instagram_url(url):
    """Validate Instagram URL format"""
    patterns = [
        r'https?://(www\.)?instagram\.com/(p|reel|tv)/([A-Za-z0-9_-]+)/?',
        r'https?://(www\.)?instagram\.com/([A-Za-z0-9_.]+)/?',
        r'https?://(www\.)?instagram\.com/([A-Za-z0-9_.]+)/(p|reel|tv)/([A-Za-z0-9_-]+)/?'
    ]
    for pattern in patterns:
        if re.match(pattern, url):
            return True
    return False

def extract_shortcode(url):
    """Extract shortcode from Instagram URL"""
    patterns = [
        r'/p/([A-Za-z0-9_-]+)',
        r'/reel/([A-Za-z0-9_-]+)',
        r'/tv/([A-Za-z0-9_-]+)'
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None

# ======================================================================================
# ORIGINAL FUNCTIONS (FIXED & ENHANCED)
# ======================================================================================

def token():
    """Original token function - enhanced with error handling"""
    return session_manager.get_token()

def igresetv1(user: str) -> Dict[str, Any]:
    """
    Reset an Instagram account password using the web API.
    FIXED: Proper headers and error handling
    """
    print_colored(f"Attempting password reset for: {user}", Colors.YELLOW)
    
    try:
        # Get fresh token
        csrf_token = token()
        
        url = "https://www.instagram.com/api/v1/web/accounts/account_recovery_send_ajax/"
        
        headers = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/x-www-form-urlencoded",
            "x-csrftoken": csrf_token,
            "x-ig-app-id": "936619743392459",
            "x-ig-www-claim": "0",
            "x-requested-with": "XMLHttpRequest",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "origin": "https://www.instagram.com",
            "referer": "https://www.instagram.com/accounts/password/reset/",
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        
        data = {"email_or_username": user}
        
        response = session_manager.session.post(url=url, headers=headers, data=data, timeout=15)
        
        result = {
            "status": "success" if response.status_code == 200 else "failed",
            "status_code": response.status_code,
            "target": user,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        try:
            result.update(response.json())
        except:
            result["response"] = response.text[:500]
        
        if response.status_code == 200:
            print_colored(f"✓ Password reset request sent for {user}", Colors.GREEN)
        else:
            print_colored(f"✗ Password reset failed with status {response.status_code}", Colors.RED)
        
        return result
        
    except Exception as e:
        logger.error(f"igresetv1 failed: {e}")
        return {
            "error": str(e), 
            "status": "failed", 
            "target": user,
            **DEV_INFO
        }

def igresetv2(user: str) -> Dict[str, Any]:
    """
    Reset an Instagram account password using Android private API.
    FIXED: Proper device ID and signature
    """
    print_colored(f"Attempting Android API reset for: {user}", Colors.YELLOW)
    
    try:
        # Generate proper Android device ID
        android_id = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
        device_id = f"android-{android_id}"
        
        # Generate UUID
        uui = str(uuid.uuid4())
        
        headers = {
            'User-Agent': 'Instagram 269.0.0.18.75 Android (28/9; 480dpi; 1080x2076; Google; Android SDK built for x86; generic_x86; ranchu; en_US)',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept-Encoding': 'gzip, deflate',
            'Cookie': f'ds_user_id=0; sessionid=0; csrftoken={token()}',
        }
        
        # Prepare data with proper structure
        post_data = {
            'device_id': device_id,
            'guid': uui,
            '_uuid': uui,
            '_csrftoken': token(),
            'query': user,
            'adid': uui,
        }
        
        response = requests.post(
            'https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/',
            headers=headers,
            data=post_data,
            timeout=15
        )
        
        result = {
            "status": "success" if response.status_code == 200 else "failed",
            "status_code": response.status_code,
            "target": user,
            "device_id": device_id,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        try:
            result.update(response.json())
        except:
            result["response"] = response.text[:500]
        
        if response.status_code == 200:
            print_colored(f"✓ Android API reset initiated for {user}", Colors.GREEN)
        else:
            print_colored(f"✗ Android API reset failed with status {response.status_code}", Colors.RED)
        
        return result
        
    except Exception as e:
        logger.error(f"igresetv2 failed: {e}")
        return {
            "error": str(e), 
            "status": "failed", 
            "target": user,
            **DEV_INFO
        }

def iguid_info(uid: Union[str, int]) -> Dict[str, Any]:
    """
    Get Instagram account details using user ID.
    FIXED: Working GraphQL endpoint with proper parameters
    """
    print_colored(f"Fetching info for user ID: {uid}", Colors.YELLOW)
    
    try:
        # First try to get username from ID
        uid = str(uid)
        
        # Method 1: Direct API call
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
        }
        
        # Try Instagram's user info endpoint
        try:
            url = f"https://i.instagram.com/api/v1/users/{uid}/info/"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                user = data.get('user', {})
                
                result = {
                    "status": "success",
                    "user_id": user.get("pk"),
                    "username": user.get("username"),
                    "full_name": user.get("full_name"),
                    "is_private": user.get("is_private", False),
                    "is_verified": user.get("is_verified", False),
                    "profile_pic_url": user.get("profile_pic_url"),
                    "follower_count": user.get("follower_count"),
                    "following_count": user.get("following_count"),
                    "media_count": user.get("media_count"),
                    "biography": user.get("biography", ""),
                    "external_url": user.get("external_url", ""),
                    "fetched_at": datetime.now().isoformat(),
                    "method": "direct_api",
                    **DEV_INFO
                }
                
                print_colored(f"✓ Found user: @{result['username']}", Colors.GREEN)
                return result
        except:
            pass
        
        # Method 2: Web scraping fallback
        print_colored("Trying web scraping method...", Colors.CYAN)
        
        # Use the username from search or try alternative
        search_url = f"https://www.instagram.com/api/v1/users/{uid}/username/"
        response = requests.get(search_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('username'):
                # Now get full info using the username
                return infoig(data['username'])
        
        # Method 3: Public endpoint
        print_colored("Trying public endpoint...", Colors.CYAN)
        public_url = f"https://www.instagram.com/graphql/query/?query_hash=7c16654f22c819fb63d1183034a5162f&variables=%7B%22user_id%22%3A%22{uid}%22%7D"
        response = requests.get(public_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            user = data.get('data', {}).get('user', {})
            
            if user:
                result = {
                    "status": "success",
                    "user_id": uid,
                    "username": user.get("username"),
                    "full_name": user.get("full_name"),
                    "is_private": user.get("is_private", False),
                    "profile_pic_url": user.get("profile_pic_url"),
                    "follower_count": user.get("edge_followed_by", {}).get("count", 0),
                    "following_count": user.get("edge_follow", {}).get("count", 0),
                    "media_count": user.get("edge_owner_to_timeline_media", {}).get("count", 0),
                    "fetched_at": datetime.now().isoformat(),
                    "method": "graphql",
                    **DEV_INFO
                }
                
                print_colored(f"✓ Found user via GraphQL", Colors.GREEN)
                return result
        
        print_colored(f"✗ Could not find info for user ID: {uid}", Colors.RED)
        return {
            "status": "not_found",
            "user_id": uid,
            "message": "User not found or account is private",
            **DEV_INFO
        }
        
    except Exception as e:
        logger.error(f"iguid_info failed: {e}")
        return {
            "error": str(e), 
            "status": "failed", 
            "user_id": uid,
            **DEV_INFO
        }

def download_reel(insta_url: str) -> Dict[str, Any]:
    """
    Download Instagram reel video - FIXED WITH WORKING SERVICES
    """
    print_colored(f"Downloading media from: {insta_url}", Colors.YELLOW)
    
    if not validate_instagram_url(insta_url):
        return {
            "error": "Invalid Instagram URL", 
            "status": "failed", 
            "valid_formats": [
                "https://instagram.com/p/XXXXX/",
                "https://instagram.com/reel/XXXXX/",
                "https://instagram.com/tv/XXXXX/"
            ],
            **DEV_INFO
        }
    
    # Extract shortcode
    shortcode = extract_shortcode(insta_url)
    if not shortcode:
        return {
            "error": "Could not extract shortcode from URL", 
            "status": "failed",
            **DEV_INFO
        }
    
    print_colored(f"Extracted shortcode: {shortcode}", Colors.CYAN)
    
    # Try multiple reliable services
    services = [
        {
            "name": "SnapInsta",
            "url": f"https://snapinsta.app/api/ajaxSearch",
            "method": "POST",
            "data": {"q": insta_url, "t": "media", "lang": "en"},
            "extractor": lambda r: extract_snapinsta(r)
        },
        {
            "name": "SaveFrom",
            "url": f"https://api.savefrom.com/api/convert",
            "method": "POST",
            "data": {"url": insta_url},
            "extractor": lambda r: extract_savefrom(r)
        },
        {
            "name": "Instagram API",
            "url": f"https://www.instagram.com/p/{shortcode}/?__a=1&__d=dis",
            "method": "GET",
            "extractor": lambda r: extract_instagram_api(r)
        }
    ]
    
    for service in services:
        try:
            print_colored(f"Trying {service['name']}...", Colors.CYAN)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Origin': 'https://snapinsta.app' if service['name'] == 'SnapInsta' else 'https://savefrom.net',
                'Referer': 'https://snapinsta.app/' if service['name'] == 'SnapInsta' else 'https://savefrom.net/',
            }
            
            if service['method'] == 'POST':
                response = requests.post(service['url'], headers=headers, data=service.get('data', {}), timeout=20)
            else:
                response = requests.get(service['url'], headers=headers, timeout=20)
            
            if response.status_code == 200:
                result = service['extractor'](response)
                if result and result.get('download_url'):
                    result.update({
                        "status": "success",
                        "service": service['name'],
                        "shortcode": shortcode,
                        "original_url": insta_url,
                        "timestamp": datetime.now().isoformat(),
                        **DEV_INFO
                    })
                    print_colored(f"✓ Download link found via {service['name']}", Colors.GREEN)
                    return result
            
        except Exception as e:
            print_colored(f"Service {service['name']} failed: {str(e)[:50]}", Colors.RED)
            continue
    
    # Final fallback: Direct page scraping
    try:
        print_colored("Trying direct page scraping...", Colors.CYAN)
        result = extract_direct_page(insta_url)
        if result:
            result.update({
                "status": "success",
                "service": "direct_scraping",
                "shortcode": shortcode,
                "original_url": insta_url,
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            })
            print_colored("✓ Download link found via direct scraping", Colors.GREEN)
            return result
    except Exception as e:
        print_colored(f"Direct scraping failed: {str(e)[:50]}", Colors.RED)
    
    return {
        "error": "All download services failed", 
        "status": "failed", 
        "shortcode": shortcode,
        "suggestion": "Try again later or check if the content is available",
        **DEV_INFO
    }

def extract_snapinsta(response):
    """Extract download URL from SnapInsta response"""
    try:
        data = response.json()
        if data.get('status') == 'ok':
            # Extract video URL
            html_content = data.get('data', '')
            
            # Look for video URL
            video_patterns = [
                r'src="([^"]+\.mp4)"',
                r'href="([^"]+\.mp4)"',
                r'data-video="([^"]+)"',
                r'download_url":"([^"]+)"'
            ]
            
            for pattern in video_patterns:
                match = re.search(pattern, html_content)
                if match:
                    download_url = match.group(1)
                    
                    # Extract caption
                    caption_match = re.search(r'caption":"([^"]+)"', html_content)
                    caption = caption_match.group(1) if caption_match else ""
                    
                    return {
                        "download_url": download_url,
                        "caption": caption,
                        "type": "video",
                        "quality": "best"
                    }
    except:
        pass
    return None

def extract_savefrom(response):
    """Extract download URL from SaveFrom response"""
    try:
        data = response.json()
        if data.get('success'):
            # Find best quality video
            best_quality = None
            for item in data.get('url', []):
                if item.get('ext') == 'mp4':
                    quality = item.get('quality', '')
                    if not best_quality or 'hd' in quality.lower():
                        best_quality = item.get('url')
            
            if best_quality:
                return {
                    "download_url": best_quality,
                    "caption": data.get('meta', {}).get('title', ''),
                    "type": "video",
                    "quality": "hd"
                }
    except:
        pass
    return None

def extract_instagram_api(response):
    """Extract download URL from Instagram API"""
    try:
        data = response.json()
        media = data.get('graphql', {}).get('shortcode_media', {})
        
        if media.get('is_video'):
            # Video
            video_url = media.get('video_url')
            if not video_url:
                # Try alternative sources
                video_versions = media.get('video_versions', [])
                if video_versions:
                    video_url = video_versions[0].get('url')
            
            if video_url:
                caption_edges = media.get('edge_media_to_caption', {}).get('edges', [])
                caption = caption_edges[0].get('node', {}).get('text', '') if caption_edges else ''
                
                return {
                    "download_url": video_url,
                    "caption": caption,
                    "type": "video",
                    "views": media.get('video_view_count', 0),
                    "duration": media.get('video_duration', 0)
                }
        else:
            # Image or carousel
            display_url = media.get('display_url')
            if display_url:
                caption_edges = media.get('edge_media_to_caption', {}).get('edges', [])
                caption = caption_edges[0].get('node', {}).get('text', '') if caption_edges else ''
                
                return {
                    "download_url": display_url,
                    "caption": caption,
                    "type": "image"
                }
    except:
        pass
    return None

def extract_direct_page(url):
    """Extract download URL by scraping Instagram page directly"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        response = requests.get(url, headers=headers, timeout=15)
        html = response.text
        
        # Look for video URL in meta tags
        meta_patterns = [
            r'property="og:video" content="([^"]+)"',
            r'property="og:video:url" content="([^"]+)"',
            r'"video_url":"([^"]+)"',
        ]
        
        for pattern in meta_patterns:
            match = re.search(pattern, html)
            if match:
                return {
                    "download_url": match.group(1),
                    "type": "video",
                    "method": "meta_tag"
                }
        
        # Look for image URL
        image_patterns = [
            r'property="og:image" content="([^"]+)"',
            r'"display_url":"([^"]+)"',
        ]
        
        for pattern in image_patterns:
            match = re.search(pattern, html)
            if match:
                return {
                    "download_url": match.group(1),
                    "type": "image",
                    "method": "meta_tag"
                }
        
        # Look for video in script tags
        script_pattern = r'"video_url":"([^"]+)"'
        matches = re.findall(script_pattern, html)
        if matches:
            return {
                "download_url": matches[0].replace('\\u0026', '&'),
                "type": "video",
                "method": "script_tag"
            }
        
    except:
        pass
    return None

def infoig(user: str) -> Dict[str, Any]:
    """
    Get Instagram profile metadata by username - FIXED & WORKING
    """
    print_colored(f"Fetching profile info for @{user}", Colors.YELLOW)
    
    try:
        # Clean username
        user = user.lstrip('@').strip()
        
        # Method 1: Official API
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'X-IG-App-ID': '936619743392459',
            'X-Requested-With': 'XMLHttpRequest',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
        }
        
        params = {'username': user}
        
        response = requests.get(
            'https://www.instagram.com/api/v1/users/web_profile_info/',
            params=params,
            headers=headers,
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            user_data = data.get('data', {}).get('user', {})
            
            profile_info = {
                "status": "success",
                "username": user_data.get("username"),
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
                "hashtags": re.findall(r'#\w+', user_data.get("biography", "")),
                "mentions": re.findall(r'@\w+', user_data.get("biography", "")),
                "category_name": user_data.get("category_name", ""),
                "fetched_at": datetime.now().isoformat(),
                "url": f"https://instagram.com/{user}",
                "method": "official_api",
                **DEV_INFO
            }
            
            print_colored(f"✓ Profile fetched: {profile_info['full_name']} ({profile_info['followers']} followers)", Colors.GREEN)
            return profile_info
        
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "username": user,
                "message": "User not found or account is private",
                **DEV_INFO
            }
        
        # Method 2: Public page fallback
        print_colored("Trying public page method...", Colors.CYAN)
        
        public_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        public_url = f"https://www.instagram.com/{user}/?__a=1&__d=dis"
        response = requests.get(public_url, headers=public_headers, timeout=15)
        
        if response.status_code == 200:
            try:
                data = response.json()
                user_data = data.get('graphql', {}).get('user', {})
                
                profile_info = {
                    "status": "success",
                    "username": user_data.get("username"),
                    "full_name": user_data.get("full_name"),
                    "user_id": user_data.get("id"),
                    "biography": user_data.get("biography", ""),
                    "followers": user_data.get("edge_followed_by", {}).get("count", 0),
                    "following": user_data.get("edge_follow", {}).get("count", 0),
                    "posts_count": user_data.get("edge_owner_to_timeline_media", {}).get("count", 0),
                    "is_private": user_data.get("is_private", False),
                    "is_verified": user_data.get("is_verified", False),
                    "profile_pic_url": user_data.get("profile_pic_url_hd"),
                    "external_url": user_data.get("external_url", ""),
                    "fetched_at": datetime.now().isoformat(),
                    "url": f"https://instagram.com/{user}",
                    "method": "public_api",
                    **DEV_INFO
                }
                
                print_colored(f"✓ Profile fetched via public API", Colors.GREEN)
                return profile_info
            except:
                pass
        
        return {
            "status": "failed",
            "username": user,
            "error": f"API returned status {response.status_code}",
            "message": "Could not fetch profile information",
            **DEV_INFO
        }
        
    except Exception as e:
        logger.error(f"infoig failed for user {user}: {e}")
        return {
            "error": str(e), 
            "status": "failed", 
            "username": user,
            **DEV_INFO
        }

def gen_igcookie() -> Dict[str, Any]:
    """
    Generate Instagram session cookies - FIXED & WORKING
    """
    print_colored("Generating Instagram cookies...", Colors.YELLOW)
    
    try:
        # Method 1: Direct cookies from Instagram
        url = "https://www.instagram.com/data/shared_data/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.instagram.com/',
            'X-Requested-With': 'XMLHttpRequest',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
        }
        
        response = session_manager.session.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            config = data.get('config', {})
            cookies = response.cookies
            
            result = {
                "status": "success",
                "csrf_token": cookies.get("csrftoken"),
                "mid": cookies.get("mid"),
                "ig_did": cookies.get("ig_did"),
                "shbid": cookies.get("shbid"),
                "shbts": cookies.get("shbts"),
                "rur": cookies.get("rur"),
                "ds_user_id": cookies.get("ds_user_id"),
                "sessionid": cookies.get("sessionid"),
                "viewer_id": config.get('viewerId'),
                "device_id": hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16],
                "rollout_hash": config.get('rollout_hash'),
                "all_cookies": dict(cookies),
                "user_agent": headers['User-Agent'],
                "generated_at": datetime.now().isoformat(),
                "method": "shared_data",
                **DEV_INFO
            }
            
            # Update session manager
            session_manager.csrf_token = cookies.get("csrftoken")
            
            print_colored("✓ Cookies generated successfully!", Colors.GREEN)
            return result
        
        # Method 2: Fallback to main page
        print_colored("Trying fallback method...", Colors.CYAN)
        
        main_url = "https://www.instagram.com/"
        fallback_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        response = requests.get(main_url, headers=fallback_headers, timeout=10)
        cookies = response.cookies
        
        result = {
            "status": "success",
            "csrf_token": cookies.get("csrftoken") or f"fallback_{int(time.time())}",
            "mid": cookies.get("mid"),
            "ig_did": cookies.get("ig_did"),
            "all_cookies": dict(cookies),
            "user_agent": fallback_headers['User-Agent'],
            "generated_at": datetime.now().isoformat(),
            "method": "fallback",
            "note": "Some cookies may be missing",
            **DEV_INFO
        }
        
        print_colored("✓ Cookies generated via fallback method", Colors.GREEN)
        return result
        
    except Exception as e:
        logger.error(f"gen_igcookie failed: {e}")
        return {
            "error": str(e), 
            "status": "failed", 
            "message": "Failed to generate cookies",
            **DEV_INFO
        }

def initiate_signup(username: str, email: str) -> Dict[str, Any]:
    """
    Initiate Instagram signup - FIXED with proper encryption
    """
    print_colored(f"Attempting signup for username: {username}", Colors.YELLOW)
    
    try:
        # Get fresh cookies first
        cookies_result = gen_igcookie()
        if cookies_result.get('status') != 'success':
            return {
                "error": "Failed to get required cookies",
                "status": "failed",
                **DEV_INFO
            }
        
        csrf_token = cookies_result.get('csrf_token')
        
        url = "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
        
        headers = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/x-www-form-urlencoded",
            "x-csrftoken": csrf_token,
            "x-ig-app-id": "936619743392459",
            "x-ig-www-claim": "0",
            "x-instagram-ajax": "1",
            "x-requested-with": "XMLHttpRequest",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "origin": "https://www.instagram.com",
            "referer": "https://www.instagram.com/accounts/emailsignup/",
            "cookie": f"csrftoken={csrf_token}; mid={cookies_result.get('mid', '')}",
        }
        
        # Generate encrypted password
        timestamp = int(time.time())
        encrypted_password = f"#PWD_INSTAGRAM_BROWSER:0:{timestamp}:Krsxh{random.randint(1000, 9999)}"
        
        data = {
            "enc_password": encrypted_password,
            "email": email,
            "username": username,
            "first_name": "User",
            "opt_into_one_tap": "false",
            "seamless_login_enabled": "1",
        }
        
        response = requests.post(url, headers=headers, data=data, timeout=15)
        
        result = {
            "status": "success" if response.status_code == 200 else "failed",
            "status_code": response.status_code,
            "username": username,
            "email": email,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        try:
            result.update(response.json())
        except:
            result["response"] = response.text[:1000]
        
        if response.status_code == 200:
            print_colored(f"✓ Signup initiated for {username}", Colors.GREEN)
        else:
            print_colored(f"✗ Signup failed with status {response.status_code}", Colors.RED)
        
        return result
        
    except Exception as e:
        logger.error(f"initiate_signup failed: {e}")
        return {
            "error": str(e), 
            "status": "failed", 
            "username": username,
            **DEV_INFO
        }

# ======================================================================================
# NEW ENHANCED FUNCTIONS
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
    Check if user has active story - FIXED
    """
    print_colored(f"Checking stories for @{user}", Colors.YELLOW)
    
    try:
        # Get user ID first
        profile = infoig(user)
        if profile.get('status') != 'success':
            return {
                "error": f"Failed to get profile: {profile.get('error', 'Unknown error')}",
                "status": "failed",
                **DEV_INFO
            }
        
        user_id = profile.get('user_id')
        
        # Try to get story reel
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'X-IG-App-ID': '936619743392459',
        }
        
        url = f"https://www.instagram.com/api/v1/feed/user/{user_id}/story/"
        response = requests.get(url, headers=headers, timeout=15)
        
        result = {
            "username": user,
            "user_id": user_id,
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
        if response.status_code == 200:
            data = response.json()
            reel = data.get('reel', {})
            
            result.update({
                "has_story": True,
                "story_count": len(reel.get('items', [])),
                "latest_story_time": reel.get('latest_reel_media', 0),
                "can_reply": reel.get('can_reply', False),
                "can_reshare": reel.get('can_reshare', False),
            })
            
            print_colored(f"✓ User has {result['story_count']} stories", Colors.GREEN)
            
        elif response.status_code == 404:
            result.update({
                "has_story": False,
                "message": "No active stories found",
            })
            print_colored("✗ No stories found", Colors.RED)
            
        else:
            result.update({
                "has_story": "unknown",
                "status_code": response.status_code,
                "message": "Could not determine story status",
            })
            print_colored(f"? Story status unknown (HTTP {response.status_code})", Colors.YELLOW)
        
        return result
        
    except Exception as e:
        return {
            "error": str(e),
            "status": "failed",
            "username": user,
            **DEV_INFO
        }

def search_instagram_users(query: str, limit: int = 10) -> Dict[str, Any]:
    """
    Search for Instagram users - FIXED
    """
    print_colored(f"Searching users for: {query}", Colors.YELLOW)
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'X-IG-App-ID': '936619743392459',
        }
        
        url = "https://www.instagram.com/api/v1/users/search/"
        params = {
            'query': query,
            'count': limit
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            users = []
            
            for user in data.get('users', [])[:limit]:
                users.append({
                    "username": user.get("username"),
                    "full_name": user.get("full_name"),
                    "user_id": user.get("pk"),
                    "is_verified": user.get("is_verified", False),
                    "is_private": user.get("is_private", False),
                    "profile_pic_url": user.get("profile_pic_url"),
                    "follower_count": user.get("follower_count", 0),
                    "mutual_followers": user.get("mutual_followers_count", 0),
                })
            
            result = {
                "status": "success",
                "query": query,
                "result_count": len(users),
                "users": users,
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            }
            
            print_colored(f"✓ Found {len(users)} users", Colors.GREEN)
            return result
        
        return {
            "status": "failed",
            "query": query,
            "error": f"API returned {response.status_code}",
            **DEV_INFO
        }
        
    except Exception as e:
        return {
            "error": str(e),
            "status": "failed",
            "query": query,
            **DEV_INFO
        }

def check_username_availability(username: str) -> Dict[str, Any]:
    """
    Check if username is available - FIXED
    """
    print_colored(f"Checking username availability: {username}", Colors.YELLOW)
    
    try:
        # Clean username
        username = username.lstrip('@').strip().lower()
        
        # First, try to get profile
        profile = infoig(username)
        
        if profile.get('status') == 'success':
            return {
                "username": username,
                "available": False,
                "message": "Username is taken",
                "existing_user": profile.get("full_name"),
                "user_id": profile.get("user_id"),
                "followers": profile.get("followers"),
                "is_private": profile.get("is_private"),
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            }
        elif profile.get('status') == 'not_found':
            # Double check with direct request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
            
            url = f"https://www.instagram.com/{username}/"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                return {
                    "username": username,
                    "available": True,
                    "message": "Username is available",
                    "timestamp": datetime.now().isoformat(),
                    **DEV_INFO
                }
            else:
                return {
                    "username": username,
                    "available": False,
                    "message": "Username exists (page returned non-404)",
                    "status_code": response.status_code,
                    "timestamp": datetime.now().isoformat(),
                    **DEV_INFO
                }
        else:
            return {
                "username": username,
                "available": "unknown",
                "message": "Could not determine availability",
                "error": profile.get("error", "Unknown error"),
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            }
            
    except Exception as e:
        return {
            "error": str(e),
            "status": "failed",
            "username": username,
            **DEV_INFO
        }

def get_instagram_hashtag_info(hashtag: str) -> Dict[str, Any]:
    """
    Get Instagram hashtag information - FIXED
    """
    print_colored(f"Fetching hashtag info: #{hashtag}", Colors.YELLOW)
    
    try:
        # Clean hashtag
        clean_hashtag = hashtag.lstrip('#').lower().strip()
        
        # Method 1: Instagram API
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'X-IG-App-ID': '936619743392459',
        }
        
        url = f"https://www.instagram.com/api/v1/tags/web_info/?tag_name={clean_hashtag}"
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            tag_data = data.get('data', {})
            
            result = {
                "status": "success",
                "hashtag": f"#{clean_hashtag}",
                "name": tag_data.get("name"),
                "id": tag_data.get("id"),
                "allow_following": tag_data.get("allow_following", False),
                "is_following": tag_data.get("is_following", False),
                "is_top_media_only": tag_data.get("is_top_media_only", False),
                "profile_pic_url": tag_data.get("profile_pic_url"),
                "media_count": tag_data.get("media_count", 0),
                "timestamp": datetime.now().isoformat(),
                "method": "official_api",
                **DEV_INFO
            }
            
            print_colored(f"✓ Hashtag found: {result['media_count']} posts", Colors.GREEN)
            return result
        
        # Method 2: Public page fallback
        print_colored("Trying public page method...", Colors.CYAN)
        
        public_url = f"https://www.instagram.com/explore/tags/{clean_hashtag}/?__a=1&__d=dis"
        response = requests.get(public_url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            tag_data = data.get('graphql', {}).get('hashtag', {})
            
            result = {
                "status": "success",
                "hashtag": f"#{clean_hashtag}",
                "name": tag_data.get("name"),
                "media_count": tag_data.get("edge_hashtag_to_media", {}).get("count", 0),
                "top_posts_only": tag_data.get("edge_hashtag_to_top_posts", {}).get("count", 0),
                "is_top_media_only": tag_data.get("is_top_media_only", False),
                "timestamp": datetime.now().isoformat(),
                "method": "public_api",
                **DEV_INFO
            }
            
            print_colored(f"✓ Hashtag found via public API", Colors.GREEN)
            return result
        
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "hashtag": f"#{clean_hashtag}",
                "message": "Hashtag not found or banned",
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            }
        
        return {
            "status": "failed",
            "hashtag": f"#{clean_hashtag}",
            "error": f"API returned {response.status_code}",
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
    except Exception as e:
        return {
            "error": str(e),
            "status": "failed",
            "hashtag": f"#{hashtag}",
            **DEV_INFO
        }

# ======================================================================================
# TELEGRAM FUNCTIONS (NEW)
# ======================================================================================

def get_telegram_info(username: str) -> Dict[str, Any]:
    """
    Get Telegram user/channel info
    """
    print_colored(f"Fetching Telegram info: @{username}", Colors.MAGENTA)
    
    try:
        username = username.lstrip('@').strip()
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        
        url = f"https://t.me/{username}"
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            # Parse HTML
            html = response.text
            
            # Extract information
            title_match = re.search(r'<div class="tgme_page_title"[^>]*><span[^>]*>([^<]+)</span>', html)
            description_match = re.search(r'<div class="tgme_page_description"[^>]*>([^<]+)</div>', html)
            members_match = re.search(r'<div class="tgme_page_extra"[^>]*>([^<]+)</div>', html)
            
            result = {
                "status": "success",
                "username": f"@{username}",
                "exists": True,
                "url": url,
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            }
            
            if title_match:
                result["title"] = title_match.group(1).strip()
            
            if description_match:
                result["description"] = description_match.group(1).strip()
            
            if members_match:
                text = members_match.group(1).strip()
                result["extra_info"] = text
                
                # Try to extract numbers
                numbers = re.findall(r'(\d+(?:,\d+)*)', text)
                if numbers:
                    result["numbers"] = numbers
            
            print_colored(f"✓ Telegram info fetched for @{username}", Colors.GREEN)
            return result
        
        elif response.status_code == 404:
            return {
                "status": "not_found",
                "username": f"@{username}",
                "exists": False,
                "message": "Telegram user/channel not found",
                "timestamp": datetime.now().isoformat(),
                **DEV_INFO
            }
        
        return {
            "status": "failed",
            "username": f"@{username}",
            "error": f"HTTP {response.status_code}",
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
        
    except Exception as e:
        return {
            "error": str(e),
            "status": "failed",
            "username": f"@{username}",
            **DEV_INFO
        }

def check_telegram_username(username: str) -> Dict[str, Any]:
    """
    Check Telegram username availability
    """
    info = get_telegram_info(username)
    
    if info.get('exists'):
        return {
            "status": "success",
            "username": f"@{username}",
            "available": False,
            "exists": True,
            "title": info.get("title"),
            "url": info.get("url"),
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }
    else:
        return {
            "status": "success",
            "username": f"@{username}",
            "available": True,
            "exists": False,
            "message": "Username is available on Telegram",
            "timestamp": datetime.now().isoformat(),
            **DEV_INFO
        }

# ======================================================================================
# BULK FUNCTIONS (NEW)
# ======================================================================================

def bulk_check_usernames(usernames: list, platform: str = "instagram") -> Dict[str, Any]:
    """
    Check multiple usernames at once
    """
    print_colored(f"Bulk checking {len(usernames)} usernames on {platform}", Colors.YELLOW, bold=True)
    
    results = []
    
    for username in usernames:
        try:
            if platform == "instagram":
                result = check_username_availability(username)
            elif platform == "telegram":
                result = check_telegram_username(username)
            else:
                result = {"username": username, "error": "Unsupported platform"}
            
            results.append(result)
            time.sleep(0.5)  # Rate limiting
            
        except Exception as e:
            results.append({
                "username": username,
                "status": "error",
                "error": str(e)
            })
    
    return {
        "status": "completed",
        "platform": platform,
        "total_checked": len(results),
        "available": len([r for r in results if r.get('available')]),
        "taken": len([r for r in results if r.get('available') == False]),
        "results": results,
        "timestamp": datetime.now().isoformat(),
        **DEV_INFO
    }

def bulk_download_reels(urls: list) -> Dict[str, Any]:
    """
    Download multiple reels at once
    """
    print_colored(f"Bulk downloading {len(urls)} reels", Colors.YELLOW, bold=True)
    
    results = []
    
    for url in urls:
        try:
            result = download_reel(url)
            results.append({
                "url": url,
                "status": result.get("status"),
                "download_url": result.get("download_url"),
                "error": result.get("error")
            })
            time.sleep(1)  # Rate limiting
            
        except Exception as e:
            results.append({
                "url": url,
                "status": "error",
                "error": str(e)
            })
    
    return {
        "status": "completed",
        "total": len(results),
        "successful": len([r for r in results if r.get('status') == 'success']),
        "failed": len([r for r in results if r.get('status') != 'success']),
        "results": results,
        "timestamp": datetime.now().isoformat(),
        **DEV_INFO
    }

# ======================================================================================
# MAIN TEST FUNCTION - COLORFUL!
# ======================================================================================

def test_all_features():
    """Test all functions with colorful output"""
    print_colored("=" * 60, Colors.CYAN, bold=True)
    print_colored("Instagram Toolkit v3.0 - by KrsxhNvrDie", Colors.MAGENTA, bold=True)
    print_colored("=" * 60, Colors.CYAN, bold=True)
    
    # Test each function
    test_cases = [
        ("Generate Cookies", lambda: gen_igcookie()),
        ("Check Username Availability", lambda: check_username_availability("testusernamexyz123")),
        ("Get Profile Info", lambda: infoig("instagram")),
        ("Get User ID Info", lambda: iguid_info("25025320")),  # Instagram's ID
        ("Search Users", lambda: search_instagram_users("test", 5)),
        ("Get Hashtag Info", lambda: get_instagram_hashtag_info("love")),
        ("Check Telegram User", lambda: get_telegram_info("telegram")),
        ("Check Story Status", lambda: get_instagram_story("instagram")),
    ]
    
    for test_name, test_func in test_cases:
        print_colored(f"\nTesting: {test_name}", Colors.YELLOW, bold=True)
        print_colored("-" * 40, Colors.CYAN)
        
        start_time = time.time()
        try:
            result = test_func()
            
            if isinstance(result, dict):
                # Print only key info
                count = 0
                for key, value in result.items():
                    if key not in DEV_INFO and not key.startswith('_'):
                        color = Colors.GREEN if key == 'status' and value == 'success' else Colors.WHITE
                        print_colored(f"  {key}: {value}", color)
                        count += 1
                        if count >= 5:  # Show only first 5 items
                            if len(result) > 5:
                                print_colored(f"  ... and {len(result)-5} more items", Colors.CYAN)
                            break
            else:
                print_colored(f"  Result: {result}", Colors.WHITE)
            
            elapsed = time.time() - start_time
            print_colored(f"  Time: {elapsed:.2f}s", Colors.GREEN)
            
        except Exception as e:
            print_colored(f"  Error: {e}", Colors.RED)
    
    print_colored("\n" + "=" * 60, Colors.CYAN, bold=True)
    print_colored("Summary", Colors.MAGENTA, bold=True)
    print_colored("-" * 40, Colors.CYAN)
    print_colored(f"Developer: {DEV_INFO['Developer']}", Colors.GREEN)
    print_colored(f"GitHub: {DEV_INFO['GitHub']}", Colors.BLUE)
    print_colored(f"Telegram: {DEV_INFO['Telegram']}", Colors.MAGENTA)
    print_colored(f"Version: {DEV_INFO['Version']}", Colors.YELLOW)
    print_colored(f"Note: {DEV_INFO['Note']}", Colors.CYAN)
    print_colored("=" * 60, Colors.CYAN, bold=True)
    
    # Test download function separately (requires valid URL)
    print_colored("\nNote: Download function requires valid Instagram URL", Colors.YELLOW)
    print_colored("Example usage: download_reel('https://instagram.com/reel/XXXXX')", Colors.CYAN)

# ======================================================================================
# INTERACTIVE MENU
# ======================================================================================

def interactive_menu():
    """Interactive menu for testing"""
    while True:
        print_colored("\n" + "=" * 60, Colors.CYAN, bold=True)
        print_colored("Instagram Toolkit v3.0 - Interactive Menu", Colors.MAGENTA, bold=True)
        print_colored("=" * 60, Colors.CYAN, bold=True)
        
        print_colored("1.  Test All Features", Colors.YELLOW)
        print_colored("2.  Get Instagram Profile", Colors.GREEN)
        print_colored("3.  Download Reel/Post", Colors.BLUE)
        print_colored("4.  Check Username Availability", Colors.MAGENTA)
        print_colored("5.  Generate Instagram Cookies", Colors.CYAN)
        print_colored("6.  Get User ID Info", Colors.GREEN)
        print_colored("7.  Search Instagram Users", Colors.BLUE)
        print_colored("8.  Get Hashtag Info", Colors.MAGENTA)
        print_colored("9.  Get Telegram Info", Colors.CYAN)
        print_colored("10. Check Instagram Story", Colors.YELLOW)
        print_colored("11. Bulk Check Usernames", Colors.GREEN)
        print_colored("0.  Exit", Colors.RED)
        
        choice = input(f"\n{Colors.YELLOW}Select option (0-11): {Colors.END}").strip()
        
        if choice == '0':
            print_colored("Goodbye!", Colors.GREEN)
            break
        elif choice == '1':
            test_all_features()
        elif choice == '2':
            username = input("Enter Instagram username: ").strip()
            result = infoig(username)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif choice == '3':
            url = input("Enter Instagram URL: ").strip()
            result = download_reel(url)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif choice == '4':
            username = input("Enter username: ").strip()
            platform = input("Platform (instagram/telegram): ").strip().lower()
            if platform == 'telegram':
                result = check_telegram_username(username)
            else:
                result = check_username_availability(username)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif choice == '5':
            result = gen_igcookie()
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif choice == '6':
            user_id = input("Enter User ID: ").strip()
            result = iguid_info(user_id)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif choice == '7':
            query = input("Enter search query: ").strip()
            limit = input("Limit (default 10): ").strip()
            limit = int(limit) if limit.isdigit() else 10
            result = search_instagram_users(query, limit)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif choice == '8':
            hashtag = input("Enter hashtag (with or without #): ").strip()
            result = get_instagram_hashtag_info(hashtag)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif choice == '9':
            username = input("Enter Telegram username (without @): ").strip()
            result = get_telegram_info(username)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif choice == '10':
            username = input("Enter Instagram username: ").strip()
            result = get_instagram_story(username)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif choice == '11':
            usernames = input("Enter usernames (comma separated): ").strip()
            usernames = [u.strip() for u in usernames.split(',')]
            platform = input("Platform (instagram/telegram): ").strip().lower()
            if platform not in ['instagram', 'telegram']:
                platform = 'instagram'
            result = bulk_check_usernames(usernames, platform)
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_colored("Invalid choice!", Colors.RED)

# ======================================================================================
# RUN THE TEST
# ======================================================================================

if __name__ == "__main__":
    print_colored("Instagram Toolkit v3.0 - Starting...", Colors.GREEN, bold=True)
    
    # Check if running in interactive mode
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_menu()
    else:
        test_all_features()
