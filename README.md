# igkrx 🚀

**igkrx** is a lightweight Python package that provides powerful Instagram tools by **Krsxh**, including:

- Fetching public Instagram profile information  
- Extracting reel metadata (caption, hashtags, video link)  
- Resetting Instagram accounts via Web & Android APIs  
- Generating fresh Instagram session cookies  
- Getting hashtag info, searching users, checking username availability  

---

## 📦 Installation

Install using pip:

```bash
pip install igkrx
```

---

## 🛠 Features & Usage

### 1️⃣ Fetch Instagram Profile Info (via username)

```python
from igkrx import infoig

info = infoig("instagram")
print(info)
```

---

### 2️⃣ Reset Instagram Account

#### Available Reset Methods:
1. **Web API → `igresetv1`**  
2. **Android API → `igresetv2`**

```python
from igkrx import igresetv1, igresetv2

# Web API reset
reset_web = igresetv1("username_or_email")
print(reset_web)

# Android API reset
reset_android = igresetv2("username_or_email")
print(reset_android)
```

---

### 3️⃣ Fetch Instagram User Info by User ID

```python
from igkrx import iguid_info

info = iguid_info("3954561043")
print(info)
```

---

### 4️⃣ Download Instagram Reels

```python
from igkrx import download_reel

data = download_reel("https://www.instagram.com/reel/XXXXXXXX/")
print(data)
```

---

### 5️⃣ Generate Instagram Cookies

```python
from igkrx import gen_igcookie

cookies = gen_igcookie()
print(cookies)
```

---

### 6️⃣ Search Instagram Users

```python
from igkrx import search_instagram_users

result = search_instagram_users("cristiano")
print(result)
```

---

### 7️⃣ Get Hashtag Info

```python
from igkrx import get_instagram_hashtag_info

tag = get_instagram_hashtag_info("travel")
print(tag)
```

---

### 8️⃣ Check Username Availability

```python
from igkrx import check_username_availability

print(check_username_availability("krsxh"))
```

---

## 📧 Contact & Author

**Author:** Krsxh  
**YouTube:** https://www.youtube.com/TechByKrsxh 
**Telegram:** https://t.me/KrsxhNvrDie
