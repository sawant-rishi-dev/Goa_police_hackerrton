# Fixed code with proper try-except structure

import os
import json
import pandas as pd
import time
import re
import argparse
import random
import urllib.parse
import csv
import logging
import sqlite3
import asyncio
import httpx
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import atexit

import streamlit as st
from dotenv import load_dotenv
import requests
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import google.generativeai as genai
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.keys import Keys
import tempfile
import shutil

# Vector database imports
try:
    import chromadb
    from chromadb.config import Settings
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False
    print("ChromaDB not available. Install with: pip install chromadb")

# Load environment variables
load_dotenv()

# App configuration
st.set_page_config(
    page_title="Advanced Online Threat Detection System",
    page_icon="🛡️",
    layout="wide"
)

# Constants
MAX_RESULTS = 10
CURRENT_DATE = datetime(2025, 10, 6)  # Current date as specified
HIGH_RISK_TLDS = ['.xyz', '.live', '.top', '.click', '.download', '.win', '.review', '.shop', '.site']
PRIVACY_KEYWORDS = ['REDACTED FOR PRIVACY', 'WhoisGuard', 'Privacy Protection', 'GDPR Masked', 'PrivacyGuard']
LOG_FILE = "logs.json"
FEEDBACK_DB = "feedback.db"

# Initialize session state
if 'results' not in st.session_state:
    st.session_state.results = []
if 'last_query' not in st.session_state:
    st.session_state.last_query = ""
if 'logs' not in st.session_state:
    st.session_state.logs = []
if 'date_range' not in st.session_state:
    st.session_state.date_range = (datetime.now() - timedelta(days=7), datetime.now())

# Initialize vector database
def init_vector_db():
    """Initialize the vector database for semantic search"""
    if not CHROMA_AVAILABLE:
        return None
    
    try:
        client = chromadb.PersistentClient(path="./vector_db")
        collection = client.get_or_create_collection(
            name="threat_intelligence",
            metadata={"hnsw:space": "cosine"}
        )
        return collection
    except Exception as e:
        print(f"Error initializing vector database: {e}")
        return None

# Initialize feedback database
def init_feedback_db():
    """Initialize the SQLite database for user feedback"""
    conn = sqlite3.connect(FEEDBACK_DB)
    cursor = conn.cursor()
    
    # Create table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        original_prediction TEXT NOT NULL,
        correct_label TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source TEXT,
        url TEXT
    )
    ''')
    
    conn.commit()
    return conn

# Save user feedback
def save_feedback(content: str, original_prediction: str, correct_label: str, source: str, url: str):
    """Save user feedback to the database"""
    conn = init_feedback_db()
    cursor = conn.cursor()
    
    cursor.execute('''
    INSERT INTO feedback (content, original_prediction, correct_label, source, url)
    VALUES (?, ?, ?, ?, ?)
    ''', (content, original_prediction, correct_label, source, url))
    
    conn.commit()
    conn.close()
    
    # Update vector database if available
    vector_collection = init_vector_db()
    if vector_collection:
        try:
            # Generate embedding for the content
            api_key = os.getenv("GEMINI_API_KEY")
            if api_key:
                genai.configure(api_key=api_key)
                
                # Add to vector database with correct label
                vector_collection.add(
                    documents=[content],
                    metadatas=[{"label": correct_label, "source": source, "url": url}],
                    ids=[f"feedback_{datetime.now().isoformat()}"]
                )
        except Exception as e:
            print(f"Error updating vector database: {e}")

# Get semantic similarity score
def get_semantic_similarity(content: str) -> float:
    """Get semantic similarity score from vector database"""
    vector_collection = init_vector_db()
    if not vector_collection:
        return 0.0
    
    try:
        # Query for similar documents
        results = vector_collection.query(
            query_texts=[content],
            n_results=5
        )
        
        if not results['documents'] or not results['documents'][0]:
            return 0.0
        
        # Calculate similarity score based on scam examples
        scam_count = 0
        total_count = len(results['metadatas'][0])
        
        for metadata in results['metadatas'][0]:
            if metadata.get('label') == 'scam':
                scam_count += 1
        
        return scam_count / total_count if total_count > 0 else 0.0
    except Exception as e:
        print(f"Error getting semantic similarity: {e}")
        return 0.0

# Asynchronous API calls
async def fetch_whois_data(domain: str):
    """Asynchronously fetch WHOIS data"""
    api_key = os.getenv("WHOIS_API_KEY")
    if not api_key:
        return {"error": "WHOIS API key not configured"}
    
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10.0)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

async def fetch_gemini_analysis(prompt: str):
    """Asynchronously fetch Gemini analysis"""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return {"error": "Gemini API key not configured"}
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-2.5-flash')
    
    try:
        response = await asyncio.to_thread(model.generate_content, prompt)
        return response.text
    except Exception as e:
        return {"error": str(e)}

# App title and description
st.title("🛡️ Advanced Online Threat Detection System")
st.markdown("Automatically detect and report on online scams, fake news, and suspicious content using advanced AI analysis and semantic understanding")

# Sidebar for configuration
with st.sidebar:
    st.header("Configuration")
    
    # Check if API keys are set
    youtube_api_key = os.getenv("YOUTUBE_API_KEY")
    gemini_api_key = os.getenv("GEMINI_API_KEY")
    whois_api_key = os.getenv("WHOIS_API_KEY")
    maps_api_key = os.getenv("GOOGLE_MAPS_API_KEY")
    
    if not youtube_api_key:
        youtube_api_key = st.text_input("YouTube API Key", type="password")
    else:
        st.success("YouTube API Key is configured")
    
    if not gemini_api_key:
        gemini_api_key = st.text_input("Gemini API Key", type="password")
    else:
        st.success("Gemini API Key is configured")
        
    if not whois_api_key:
        whois_api_key = st.text_input("WHOIS API Key", type="password")
    else:
        st.success("WHOIS API Key is configured")
        
    if not maps_api_key:
        maps_api_key = st.text_input("Google Maps API Key", type="password")
    else:
        st.success("Google Maps API Key is configured")
    
    # Update environment variables if provided
    if youtube_api_key:
        os.environ["YOUTUBE_API_KEY"] = youtube_api_key
    if gemini_api_key:
        os.environ["GEMINI_API_KEY"] = gemini_api_key
    if whois_api_key:
        os.environ["WHOIS_API_KEY"] = whois_api_key
    if maps_api_key:
        os.environ["GOOGLE_MAPS_API_KEY"] = maps_api_key
    
    # Date range selection
    st.header("Date Range")
    date_range = st.date_input(
        "Search content within a specific range",
        st.session_state.date_range,
        format="YYYY-MM-DD"
    )
    st.session_state.date_range = date_range

# Main content
col1, col2 = st.columns([3, 1])

with col1:
    search_query = st.text_input("Search for potential threats", placeholder="Enter search terms...")
    
with col2:
    st.write("")  # Add some space
    search_button = st.button("Search & Analyze", type="primary")

# Initialize Chrome driver
def initialize_driver(profile_path: str = None):
    """
    Configures and launches the Chrome WebDriver.
    
    Args:
        profile_path (str, optional): Path to Chrome user profile directory
        
    Returns:
        WebDriver: Configured Chrome WebDriver instance
    """
    print("Initializing Chrome WebDriver...")
    
    options = webdriver.ChromeOptions()
    
    # Create a temporary profile directory if none provided
    if not profile_path:
        temp_dir = tempfile.mkdtemp(prefix='chrome_profile_')
        profile_path = temp_dir
        print(f"Using temporary Chrome profile at: {profile_path}")
        # Set to delete the temp directory when done
        atexit.register(lambda: shutil.rmtree(temp_dir, ignore_errors=True))
    else:
        # If a profile path is provided, make sure it's not already in use
        # by checking if the directory exists and creating a unique one if needed
        if os.path.exists(profile_path):
            # Create a unique profile path with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            profile_path = f"{profile_path}_{timestamp}"
            print(f"Profile path already in use, creating unique profile: {profile_path}")
            # Set to delete the temp directory when done
            atexit.register(lambda: shutil.rmtree(profile_path, ignore_errors=True))
    
    # Add profile path if provided
    if profile_path:
        options.add_argument(f'--user-data-dir={profile_path}')
        print(f"Using Chrome profile at: {profile_path}")
    
    # Additional options to help avoid detection
    options.add_argument('--disable-blink-features=AutomationControlled')
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)
    
    # Disable the DevTools port to avoid conflicts
    options.add_argument("--remote-debugging-port=0")
    options.add_argument("--disable-extensions")
    
    # Initialize the driver
    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()), 
        options=options
    )
    
    # Execute script to further mask automation
    driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
    
    print("Chrome driver initialized successfully")
    return driver

# Load fraud keywords from CSV files
def load_fraud_keywords():
    """
    Loads fraud keywords from the provided CSV files.
    
    Returns:
        Dict: Dictionary containing fraud keywords by category
    """
    fraud_keywords = {
        'general': [],
        'financial': [],
        'credit_card_identity': [],
        'email_phishing': [],
        'corporate': [],
        'insurance': [],
        'red_flags': [],
        'prostitution': [],
        'gambling': [],
        'community_sourced': []
    }
    
    fraudulent_activities = {
        'social_media_ads': [],
        'investment_groups': [],
        'fake_hotels': [],
        'prostitution': [],
        'gambling': []
    }
    
    try:
        # Load fraud_keywords.csv
        if os.path.exists("fraud_keywords.csv"):
            with open("fraud_keywords.csv", 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    category = row.get('Category', '').lower().replace(' ', '_').replace('/', '_')
                    keyword = row.get('Keyword/Hashtag', '').strip()
                    
                    if category in fraud_keywords and keyword:
                        fraud_keywords[category].append(keyword.lower())
        
        # Load fraudulent_activity_keywords.csv
        if os.path.exists("fraudulent_activity_keywords.csv"):
            with open("fraudulent_activity_keywords.csv", 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    activity_type = row.get('Fraudulent activity type', '').strip()
                    keywords = row.get('Hashtags and Keywords', '').strip()
                    
                    if activity_type == "Fraudulent Ads on social media":
                        fraudulent_activities['social_media_ads'].extend([k.strip().lower() for k in keywords.split('/') if k.strip()])
                    elif activity_type == "Fraudulent groups for investment/trading":
                        fraudulent_activities['investment_groups'].append(keywords.lower())
                    elif activity_type == "Fraudulent Ads for fake hotels/Airbnb/resorts":
                        fraudulent_activities['fake_hotels'].append(keywords.lower())
                    elif activity_type == "Fraudulent Ads and content on prostitution":
                        fraudulent_activities['prostitution'].extend([k.strip().lower() for k in keywords.split(',') if k.strip()])
                    elif activity_type == "Fraudulent Ads and content on gambling":
                        fraudulent_activities['gambling'].extend([k.strip().lower() for k in keywords.split(',') if k.strip()])
        
        return fraud_keywords, fraudulent_activities
    except Exception as e:
        print(f"Error loading fraud keywords: {e}")
        return fraud_keywords, fraudulent_activities

# Log function to save logs to JSON file
def log_activity(activity_type: str, details: Dict):
    """
    Logs activity to a JSON file.
    
    Args:
        activity_type (str): Type of activity (e.g., 'search', 'analysis', 'detection')
        details (Dict): Details of the activity
    """
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': activity_type,
        'details': details
    }
    
    # Add to session state logs
    st.session_state.logs.append(log_entry)
    
    # Save to file
    try:
        logs = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8') as file:
                logs = json.load(file)
        
        logs.append(log_entry)
        
        with open(LOG_FILE, 'w', encoding='utf-8') as file:
            json.dump(logs, file, indent=2)
    except Exception as e:
        print(f"Error logging activity: {e}")

# Check content against fraud keywords
def check_fraud_keywords(content: str, fraud_keywords: Dict, fraudulent_activities: Dict) -> Dict:
    """
    Checks content against fraud keywords and returns matches.
    
    Args:
        content (str): Content to check
        fraud_keywords (Dict): Dictionary of fraud keywords by category
        fraudulent_activities (Dict): Dictionary of fraudulent activity keywords
        
    Returns:
        Dict: Dictionary containing matched keywords and categories
    """
    content_lower = content.lower()
    matches = {
        'categories': {},
        'keywords': [],
        'risk_score': 0,
        'reasons': []
    }
    
    # Check against fraud keywords
    for category, keywords in fraud_keywords.items():
        category_matches = []
        for keyword in keywords:
            if keyword in content_lower:
                category_matches.append(keyword)
                matches['keywords'].append(keyword)
                
                # Add to reasons
                if category == 'general':
                    matches['reasons'].append(f"General fraud indicator: '{keyword}'")
                    matches['risk_score'] += 5
                elif category == 'financial':
                    matches['reasons'].append(f"Financial fraud indicator: '{keyword}'")
                    matches['risk_score'] += 10
                elif category == 'credit_card_identity':
                    matches['reasons'].append(f"Credit card/identity fraud indicator: '{keyword}'")
                    matches['risk_score'] += 10
                elif category == 'email_phishing':
                    matches['reasons'].append(f"Email/phishing fraud indicator: '{keyword}'")
                    matches['risk_score'] += 8
                elif category == 'corporate':
                    matches['reasons'].append(f"Corporate fraud indicator: '{keyword}'")
                    matches['risk_score'] += 7
                elif category == 'insurance':
                    matches['reasons'].append(f"Insurance fraud indicator: '{keyword}'")
                    matches['risk_score'] += 7
                elif category == 'red_flags':
                    matches['reasons'].append(f"Red flag indicator: '{keyword}'")
                    matches['risk_score'] += 8
                elif category == 'prostitution':
                    matches['reasons'].append(f"Prostitution indicator: '{keyword}'")
                    matches['risk_score'] += 5
                elif category == 'gambling':
                    matches['reasons'].append(f"Gambling indicator: '{keyword}'")
                    matches['risk_score'] += 5
                elif category == 'community_sourced':
                    matches['reasons'].append(f"Community-sourced fraud indicator: '{keyword}'")
                    matches['risk_score'] += 6
        
        if category_matches:
            matches['categories'][category] = category_matches
    
    # Check against fraudulent activities
    for activity, keywords in fraudulent_activities.items():
        activity_matches = []
        for keyword in keywords:
            if keyword in content_lower:
                activity_matches.append(keyword)
                matches['keywords'].append(keyword)
                
                # Add to reasons
                if activity == 'social_media_ads':
                    matches['reasons'].append(f"Fraudulent social media ad indicator: '{keyword}'")
                    matches['risk_score'] += 8
                elif activity == 'investment_groups':
                    matches['reasons'].append(f"Fraudulent investment group indicator: '{keyword}'")
                    matches['risk_score'] += 10
                elif activity == 'fake_hotels':
                    matches['reasons'].append(f"Fake hotel indicator: '{keyword}'")
                    matches['risk_score'] += 9
                elif activity == 'prostitution':
                    matches['reasons'].append(f"Prostitution activity indicator: '{keyword}'")
                    matches['risk_score'] += 5
                elif activity == 'gambling':
                    matches['reasons'].append(f"Gambling activity indicator: '{keyword}'")
                    matches['risk_score'] += 5
        
        if activity_matches:
            if 'activities' not in matches:
                matches['activities'] = {}
            matches['activities'][activity] = activity_matches
    
    return matches

# Extract domains from content
def extract_domains_from_content(content: str) -> List[str]:
    """
    Extracts domain names from text content.
    
    Args:
        content (str): Text content to extract domains from
        
    Returns:
        List[str]: List of unique domain names found in the content
    """
    # Regular expression to find URLs in text
    url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
    urls = re.findall(url_pattern, content)
    
    # Extract domains from URLs
    domains = []
    for url in urls:
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            # Remove www. if present
            if domain.startswith("www."):
                domain = domain[4:]
            
            # Skip common social media domains
            social_media_domains = [
                'facebook.com', 'instagram.com', 'youtube.com', 'twitter.com',
                'linkedin.com', 'tiktok.com', 'reddit.com', 'pinterest.com'
            ]
            
            if domain and domain not in social_media_domains:
                domains.append(domain)
        except:
            continue
    
    # Also look for domain patterns without http/https
    domain_pattern = r'(?:^|\s)(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})(?:\s|$)'
    plain_domains = re.findall(domain_pattern, content)
    
    for domain in plain_domains:
        # Skip common social media domains
        social_media_domains = [
            'facebook.com', 'instagram.com', 'youtube.com', 'twitter.com',
            'linkedin.com', 'tiktok.com', 'reddit.com', 'pinterest.com'
        ]
        
        if domain and domain not in social_media_domains:
            domains.append(domain)
    
    # Return unique domains
    return list(set(domains))

# ScamAdviser-like website analysis
@st.cache_data(ttl=3600)  # Cache for 1 hour
def analyze_website_like_scamadviser(url: str, title: str, description: str) -> Dict:
    """
    Analyzes a website using ScamAdviser-like methodology.
    
    Args:
        url (str): URL of the website to analyze
        title (str): Title of the website
        description (str): Description/snippet of the website
        
    Returns:
        Dict: ScamAdviser-like analysis results
    """
    print(f"Performing ScamAdviser-like analysis for: {url}")
    log_activity('scamadviser_analysis', {'url': url})
    
    try:
        # Extract domain from URL
        if not url.startswith("http"):
            url = "https://" + url
            
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove www. if present
        if domain.startswith("www."):
            domain = domain[4:]
        
        # Initialize result with default values
        result = {
            "url": url,
            "domain": domain,
            "domain_age": "Unknown",
            "trust_score": 50,  # Default neutral score
            "ssl_certificate": "Unknown",
            "server_location": "Unknown",
            "content_red_flags": [],
            "phishing_indicators": "No",
            "user_reviews": "None Found",
            "technical_issues": [],
            "final_verdict": "Suspicious",
            "confidence_score": 0.5,
            "recommendation": "Proceed with caution"
        }
        
        # Get WHOIS data for domain age and registration info
        try:
            api_key = os.getenv("WHOIS_API_KEY")
            if api_key:
                whois_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
                whois_response = requests.get(whois_url)
                whois_data = whois_response.json()
                
                # Extract domain age
                creation_date_str = whois_data.get('WhoisRecord', {}).get('createdDate', 'Not available')
                if creation_date_str != 'Not available':
                    try:
                        if isinstance(creation_date_str, list):
                            creation_date_str = creation_date_str[0]
                        
                        # Handle different date formats
                        if 'T' in creation_date_str:
                            creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
                        else:
                            creation_date = datetime.strptime(creation_date_str.split(' ')[0], '%Y-%m-%d')
                        
                        # Calculate domain age
                        days_since_creation = (CURRENT_DATE - creation_date.replace(tzinfo=None)).days
                        
                        if days_since_creation <= 30:
                            result["domain_age"] = "Less than 1 month"
                            result["trust_score"] -= 30
                            result["content_red_flags"].append("Very new domain (less than 1 month)")
                        elif days_since_creation <= 180:
                            result["domain_age"] = "Less than 6 months"
                            result["trust_score"] -= 20
                            result["content_red_flags"].append("New domain (less than 6 months)")
                        elif days_since_creation <= 365:
                            result["domain_age"] = "Less than 1 year"
                            result["trust_score"] -= 10
                        elif days_since_creation <= 1825:  # 5 years
                            result["domain_age"] = f"{days_since_creation // 365} years"
                        else:
                            result["domain_age"] = "More than 5 years"
                            result["trust_score"] += 15
                    except Exception as e:
                        print(f"Error parsing creation date: {e}")
                
                # Check for privacy protection
                registrant_info = whois_data.get('WhoisRecord', {}).get('registrant', {}).get('organization', 'Not available')
                if registrant_info != 'Not available':
                    for keyword in PRIVACY_KEYWORDS:
                        if keyword.lower() in str(registrant_info).lower():
                            result["content_red_flags"].append(f"Hidden identity: {keyword}")
                            result["trust_score"] -= 15
                            break
                
                # Get registrar info
                registrar = whois_data.get('WhoisRecord', {}).get('registrarName', 'Unknown')
                if registrar:
                    result["registrar"] = registrar
        except Exception as e:
            print(f"Error getting WHOIS data: {e}")
        
        # Check SSL certificate
        try:
            import ssl
            import socket
            from datetime import datetime
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check if certificate is valid
                    if cert:
                        # Check expiration
                        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expire_date - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            result["ssl_certificate"] = "Expiring Soon"
                            result["trust_score"] -= 10
                            result["technical_issues"].append("SSL certificate expiring soon")
                        else:
                            result["ssl_certificate"] = "Valid"
                            result["trust_score"] += 5
                    else:
                        result["ssl_certificate"] = "Invalid"
                        result["trust_score"] -= 20
                        result["technical_issues"].append("Invalid SSL certificate")
        except Exception as e:
            result["ssl_certificate"] = "Invalid/Not Found"
            result["trust_score"] -= 20
            result["technical_issues"].append("No valid SSL certificate")
        
        # Check server location
        try:
            import ipaddress
            # Get IP address
            ip_address = socket.gethostbyname(domain)
            
            # Use ip-api.com to get location
            location_response = requests.get(f"http://ip-api.com/json/{ip_address}")
            if location_response.status_code == 200:
                location_data = location_response.json()
                country = location_data.get('country', 'Unknown')
                result["server_location"] = country
                
                # High-risk countries
                high_risk_countries = ['Russia', 'China', 'Nigeria', 'North Korea', 'Iran']
                if country in high_risk_countries:
                    result["trust_score"] -= 15
                    result["content_red_flags"].append(f"Server located in high-risk country: {country}")
        except Exception as e:
            print(f"Error getting server location: {e}")
        
        # Analyze content for red flags
        content = f"{title} {description}".lower()
        
        # Check for too-good-to-be-true offers
        too_good_phrases = [
            "guaranteed return", "100% free", "risk free", "double your money",
            "get rich quick", "instant profit", "no risk", "guaranteed profit"
        ]
        for phrase in too_good_phrases:
            if phrase in content:
                result["content_red_flags"].append(f"Too-good-to-be-true offer: '{phrase}'")
                result["trust_score"] -= 10
        
        # Check for urgency tactics
        urgency_phrases = [
            "act now", "limited time", "offer expires", "don't miss out",
            "last chance", "hurry up", "only today", "while stocks last"
        ]
        for phrase in urgency_phrases:
            if phrase in content:
                result["content_red_flags"].append(f"Urgency tactic: '{phrase}'")
                result["trust_score"] -= 5
        
        # Check for phishing indicators
        # Look for brand impersonation
        brands = ['paypal', 'amazon', 'facebook', 'google', 'microsoft', 'apple', 'netflix']
        for brand in brands:
            if brand in content and brand not in domain:
                result["phishing_indicators"] = "Yes"
                result["content_red_flags"].append(f"Potential brand impersonation: mentions {brand} but not in domain")
                result["trust_score"] -= 25
        
        # Check for suspicious URL patterns
        suspicious_patterns = [
            r'.*\.tk$', r'.*\.ml$', r'.*\.ga$', r'.*\.cf$',
            r'.*-[0-9]+\..*', r'.*[0-9]{5,}\..*'
        ]
        for pattern in suspicious_patterns:
            if re.match(pattern, domain):
                result["content_red_flags"].append(f"Suspicious domain pattern: {pattern}")
                result["trust_score"] -= 10
        
        # Check for HTTP instead of HTTPS
        if url.startswith("http://"):
            result["technical_issues"].append("Uses HTTP instead of HTTPS")
            result["trust_score"] -= 15
        
        # Determine final verdict based on trust score
        if result["trust_score"] >= 70:
            result["final_verdict"] = "Legitimate"
            result["confidence_score"] = 0.8
            result["recommendation"] = "Safe to proceed"
        elif result["trust_score"] >= 40:
            result["final_verdict"] = "Suspicious"
            result["confidence_score"] = 0.6
            result["recommendation"] = "Proceed with caution"
        else:
            result["final_verdict"] = "Fraudulent"
            result["confidence_score"] = 0.9
            result["recommendation"] = "Avoid entirely"
        
        # Ensure trust score is within 0-100 range
        result["trust_score"] = max(0, min(100, result["trust_score"]))
        
        log_activity('scamadviser_result', {
            'url': url, 
            'trust_score': result["trust_score"], 
            'verdict': result["final_verdict"]
        })
        
        return result
        
    except Exception as e:
        error_result = {
            "url": url,
            "error": f"Error analyzing website: {str(e)}",
            "final_verdict": "Unknown",
            "confidence_score": 0.0,
            "recommendation": "Unable to analyze"
        }
        log_activity('error', {'type': 'scamadviser', 'url': url, 'message': str(e)})
        return error_result

# Threat Intelligence Analyst Analysis
def threat_intelligence_analysis(content: str, source: str, url: str, keyword_matches: Dict) -> Dict:
    """
    Performs a comprehensive threat intelligence analysis of content to identify psychological manipulation tactics.
    
    Args:
        content (str): Content to analyze
        source (str): Source of the content
        url (str): URL of the content
        keyword_matches (Dict): Keyword matches from previous analysis
        
    Returns:
        Dict: Threat intelligence analysis results
    """
    print(f"Performing threat intelligence analysis for content from {source}")
    log_activity('threat_intelligence_analysis', {'source': source, 'url': url})
    
    try:
        # Calculate semantic risk score from vector database
        semantic_score = get_semantic_similarity(content)
        
        # Calculate semantic risk score from keyword matches
        keyword_score = min(1.0, keyword_matches.get('risk_score', 0) / 50.0)
        
        # Combine scores
        combined_score = (semantic_score * 0.7) + (keyword_score * 0.3)
        
        # Format keyword matches for the prompt
        keyword_matches_str = ", ".join(keyword_matches.get('keywords', []))
        
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return {
                "risk_score": int(combined_score * 100),
                "is_scam": combined_score > 0.5,
                "confidence": combined_score,
                "scam_type": "Unknown",
                "summary": "Unable to perform detailed threat intelligence analysis: API key not configured",
                "reasoning": f"Based on semantic similarity: {semantic_score:.2f} and keyword matching: {keyword_score:.2f}",
                "red_flags": []
            }
            
        genai.configure(api_key=api_key)
        
        model_names = ['gemini-2.5-flash']
        model = None
        
        for model_name in model_names:
            try:
                model = genai.GenerativeModel(model_name)
                break
            except Exception:
                continue
                
        if not model:
            return {
                "risk_score": int(combined_score * 100),
                "is_scam": combined_score > 0.5,
                "confidence": combined_score,
                "scam_type": "Unknown",
                "summary": "Unable to perform detailed threat intelligence analysis: No compatible model available",
                "reasoning": f"Based on visual similarity: {semantic_score:.2f} and keyword matching: {keyword_score:.2f}",
                "red_flags": []
            }
        
        prompt = f"""
        Act as a world-class Threat Intelligence Analyst with expertise in financial fraud, psychological manipulation, and cybersecurity. Your mission is to perform a rigorous, multi-faceted analysis of the provided content and deliver a structured risk assessment.

        **CONTEXT:**
        - **Source Platform:** {source}
        - **Content URL:** {url}
        - **Initial Semantic Risk Score:** {semantic_score:.2f} (A score from 0.0 to 1.0 indicating similarity to known verified scams)
        - **Keyword Matching Score:** {keyword_score:.2f} (A score from 0.0 to 1.0 based on keyword matches)
        - **Matching Keyword Indicators:** {keyword_matches_str}

        **CONTENT FOR ANALYSIS:**
        ---
        {content}
        ---

        **ANALYTICAL TASKS:**
        1.  **Deconstruct the Narrative:** Identify the core message, the offer being made, and the target audience.
        2.  **Identify Psychological Tactics:** Analyze the text for specific manipulation techniques, including but not limited to:
            - **Urgency/Scarcity:** (e.g., "limited time," "only 2 spots left")
            - **Authority/Social Proof:** (e.g., "as seen on TV," fake celebrity endorsements, "95% of our users profit")
            - **Promise of Unrealistic Gains:** (e.g., "guaranteed 10x return," "risk-free investment")
            - **Fear of Missing Out (FOMO):** (e.g., "don't be the one who missed out")
            - **Vague Technobabble:** Using complex jargon to appear legitimate without providing substance.
        3.  **Assess Actionable Risk:** What is the user being asked to do? (e.g., click a link, join a Telegram group, provide personal info, connect a crypto wallet). How risky is this action?
        4.  **Synthesize Findings:** Based on the context and your analysis, determine the overall threat level.

        **REQUIRED OUTPUT FORMAT (Strictly JSON):**
        Provide your response as a single, valid JSON object. Do not include any text or formatting outside of this JSON structure.

        {{
          "risk_score": <An integer from 0 (benign) to 100 (highly malicious)>,
          "is_scam": <boolean, true or false>,
          "confidence": <float, from 0.0 to 1.0, your confidence in the is_scam verdict>,
          "scam_type": "<A specific classification, e.g., 'Phishing', 'Ponzi Scheme', 'Crypto Pump & Dump', 'Advance-Fee Fraud', 'Fake E-commerce', 'Not a Scam'>",
          "summary": "<A one-sentence executive summary of the threat.>",
          "reasoning": "<A step-by-step 'chain-of-thought' explaining how you arrived at your conclusion, referencing the psychological tactics and other indicators.>",
          "red_flags": [
            {{
              "flag": "<The name of the identified red flag, e.g., 'Unrealistic Promise'>",
              "evidence": "<The exact quote from the text that demonstrates this flag.>"
            }},
            {{
              "flag": "<e.g., 'High-Pressure Urgency'>",
              "evidence": "<e.g., 'This offer expires in 5 minutes!'>"
            }}
          ]
        }}
        """
        
        # Implement retry logic with exponential backoff
        max_retries = 3
        base_delay = 6  # Start with 6 seconds delay to stay within rate limits
        
        for attempt in range(max_retries):
            try:
                response = model.generate_content(prompt)
                response_text = response.text
                
                try:
                    if "```json" in response_text:
                        response_text = response_text.split("```json")[1].split("```")[0]
                    elif "```" in response_text:
                        response_text = response_text.split("```")[1].split("```")[0]
                        
                    analysis_result = json.loads(response_text)
                    
                    # Validate required fields
                    required_fields = ["risk_score", "is_scam", "confidence", "scam_type", "summary", "reasoning", "red_flags"]
                    for field in required_fields:
                        if field not in analysis_result:
                            raise ValueError(f"Missing required field: {field}")
                    
                    # Log the analysis
                    log_activity('threat_intelligence_result', {
                        'source': source, 
                        'url': url, 
                        'risk_score': analysis_result['risk_score'],
                        'is_scam': analysis_result['is_scam'],
                        'scam_type': analysis_result['scam_type']
                    })
                    
                    return analysis_result
                except (json.JSONDecodeError, ValueError) as e:
                    print(f"Error parsing threat intelligence response: {e}")
                    # Return a default response if parsing fails
                    return {
                        "risk_score": int(combined_score * 100),
                        "is_scam": combined_score > 0.5,
                        "confidence": combined_score,
                        "scam_type": "Unknown",
                        "summary": f"Failed to parse analysis: {str(e)}",
                        "reasoning": f"Based on visual similarity: {semantic_score:.2f} and keyword matching: {keyword_score:.2f}",
                        "red_flags": []
                    }
            
            except Exception as e:
                if "429" in str(e) and attempt < max_retries - 1:
                    # Rate limit error, wait and retry
                    delay = base_delay * (2 ** attempt)  # Exponential backoff
                    print(f"Rate limit reached. Waiting {delay} seconds before retrying...")
                    time.sleep(delay)
                else:
                    # Non-rate limit error or max retries reached
                    print(f"Error during threat intelligence analysis: {e}")
                    return {
                        "risk_score": int(combined_score * 100),
                        "is_scam": combined_score > 0.5,
                        "confidence": combined_score,
                        "scam_type": "Unknown",
                        "summary": f"Analysis failed: {str(e)}",
                        "reasoning": f"Based on visual similarity: {semantic_score:.2f} and keyword matching: {keyword_score:.2f}",
                        "red_flags": []
                    }
            
            # Add a delay between requests to avoid hitting rate limits
            if attempt < max_retries - 1:
                time.sleep(6)  # 6 seconds delay to stay within the 10 requests/minute limit
            
    except Exception as e:
        print(f"Unexpected error during threat intelligence analysis: {e}")
        log_activity('error', {'type': 'threat_intelligence', 'url': url, 'message': str(e)})
        return {
            "risk_score": int(combined_score * 100),
            "is_scam": combined_score > 0.5,
            "confidence": combined_score,
            "scam_type": "Unknown",
            "summary": f"Analysis failed: {str(e)}",
            "reasoning": f"Based on visual similarity: {semantic_score:.2f} and keyword matching: {keyword_score:.2f}",
            "red_flags": []
        }

# Google Search Scraper
def search_google(driver, query: str, max_results: int = MAX_RESULTS, date_range=None):
    """
    Performs a Google search and scrapes the top results.
    
    Args:
        driver (WebDriver): Selenium WebDriver instance
        query (str): Search query
        max_results (int): Maximum number of results to return
        date_range (tuple): Tuple of (start_date, end_date) for date filtering
        
    Returns:
        list: List of dictionaries containing search result data
    """
    print(f"Searching Google for: {query}")
    log_activity('search', {'platform': 'Google', 'query': query})
    
    results = []
    
    try:
        # Sanitize the query for URL
        sanitized_query = urllib.parse.quote_plus(query)
        
        # Add date filter if provided
        date_filter = ""
        if date_range:
            start_date, end_date = date_range
            start_date_str = start_date.strftime('%m/%d/%Y')
            end_date_str = end_date.strftime('%m/%d/%Y')
            date_filter = f"&tbs=cdr:1,cd_min:{start_date_str},cd_max:{end_date_str}"
        
        # Construct the base URL
        search_url = f"https://www.google.com/search?q={sanitized_query}{date_filter}"
        
        print(f"URL: {search_url}")
        
        # Navigate to the URL
        driver.get(search_url)
        
        # Wait for results to load
        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "search"))
            )
            print("Search results loaded successfully")
        except TimeoutException:
            print("Warning: Search results did not load in time")
        
        # Add a small delay to ensure all elements are loaded
        time.sleep(random.uniform(1, 2))
        
        # Find all search result containers
        selectors = [
            "div.g",  # Standard search result
            "div.MjjYud",  # New container
            "div.tF2Cxc",  # Another possible container
            "div.hlcw0c",  # Yet another possible container
            "div.yuRUbf",  # URL container
            "div[role='heading']"  # Heading container
        ]
        
        search_results = []
        for selector in selectors:
            try:
                search_results = driver.find_elements(By.CSS_SELECTOR, selector)
                if search_results:
                    print(f"Found {len(search_results)} results with selector: {selector}")
                    break
            except:
                continue
        
        if not search_results:
            print("No search results found")
            return results
        
        print(f"Found {len(search_results)} potential results")
        
        # Limit to the specified number of results
        search_results = search_results[:max_results]
        
        # Extract data from each result
        for i, result in enumerate(search_results):
            try:
                # Extract title - updated selectors
                title_element = None
                title_selectors = [
                    "h3",
                    "h3.LC20lb",
                    "h3.DKV0Md",
                    "div[role='heading'] span",
                    "a h3",
                    "a span",
                    "div[role='heading']",
                    "span.VuuXrf"
                ]
                
                for selector in title_selectors:
                    try:
                        title_element = result.find_element(By.CSS_SELECTOR, selector)
                        if title_element and title_element.text.strip():
                            break
                    except:
                        continue
                
                title = title_element.text.strip() if title_element else "No title found"
                
                # Extract URL - updated selectors
                url_element = None
                url_selectors = [
                    "a",
                    "a[href]",
                    "div.yuRUbf a",
                    "a[jsname]",
                    "div[data-ved] a",
                    "div.tF2Cxc a",
                    "div.MjjYud a"
                ]
                
                for selector in url_selectors:
                    try:
                        url_element = result.find_element(By.CSS_SELECTOR, selector)
                        if url_element and url_element.get_attribute("href"):
                            break
                    except:
                        continue
                
                url = url_element.get_attribute("href") if url_element else "No URL found"
                
                # Extract description/snippet - updated selectors
                snippet_element = None
                snippet_selectors = [
                    "div.VwiC3b",
                    "div.s",
                    "span.aCOpRe",
                    "div.IsZvec",
                    "div[style='-webkit-line-clamp:2']",
                    "div[style='-webkit-line-clamp:3']",
                    "div.YrbPuc",
                    "div.sXLaOe"
                ]
                
                for selector in snippet_selectors:
                    try:
                        snippet_element = result.find_element(By.CSS_SELECTOR, selector)
                        if snippet_element and snippet_element.text.strip():
                            break
                    except:
                        continue
                
                snippet = snippet_element.text.strip() if snippet_element else "No description found"
                
                # Only add if we have at least a title and URL
                if title != "No title found" and url != "No URL found":
                    results.append({
                        'title': title,
                        'url': url,
                        'snippet': snippet,
                        'source': 'Google'
                    })
                
            except Exception as e:
                print(f"Error extracting result {i+1}: {str(e)}")
                continue
        
        print(f"Successfully extracted {len(results)} results")
        log_activity('search_results', {'platform': 'Google', 'count': len(results)})
        
    except Exception as e:
        print(f"Error scraping Google search results: {str(e)}")
        log_activity('error', {'platform': 'Google', 'message': str(e)})
    
    return results

# YouTube Search
def search_youtube_videos(query: str, max_results: int = MAX_RESULTS, date_range=None) -> List[Dict]:
    """
    Searches YouTube for videos related to a query.
    
    Args:
        query (str): Search query
        max_results (int): Maximum number of results to return
        date_range (tuple): Tuple of (start_date, end_date) for date filtering
        
    Returns:
        List[Dict]: List of video information
    """
    print(f"Searching YouTube for: {query}")
    log_activity('search', {'platform': 'YouTube', 'query': query})
    
    try:
        api_key = os.getenv("YOUTUBE_API_KEY")
        if not api_key:
            st.error("YouTube API key not found. Please configure it in the sidebar.")
            return []
            
        youtube = build('youtube', 'v3', developerKey=api_key)
        
        # Add date filter if provided
        search_params = {
            'q': query,
            'part': 'snippet',
            'type': 'video',
            'maxResults': max_results
        }
        
        if date_range:
            start_date, end_date = date_range
            # Convert dates to RFC 3339 format
            start_date_iso = start_date.isoformat("T") + "Z"
            end_date_iso = end_date.isoformat("T") + "Z"
            search_params['publishedAfter'] = start_date_iso
            search_params['publishedBefore'] = end_date_iso
        
        search_response = youtube.search().list(**search_params).execute()
        
        videos = []
        for item in search_response['items']:
            video_id = item['id']['videoId']
            title = item['snippet']['title']
            description = item['snippet']['description']
            
            videos.append({
                'videoId': video_id,
                'title': title,
                'description': description,
                'url': f"https://www.youtube.com/watch?v={video_id}",
                'source': 'YouTube'
            })
            
        print(f"Successfully extracted {len(videos)} YouTube videos")
        log_activity('search_results', {'platform': 'YouTube', 'count': len(videos)})
        return videos
        
    except HttpError as e:
        st.error(f"Error accessing YouTube API: {e}")
        log_activity('error', {'platform': 'YouTube', 'message': str(e)})
        return []
    except Exception as e:
        st.error(f"Unexpected error during YouTube search: {e}")
        log_activity('error', {'platform': 'YouTube', 'message': str(e)})
        return []

# Facebook Search
def search_facebook(driver, query: str, max_results: int = MAX_RESULTS):
    """
    Searches Facebook for posts related to a query.
    
    Args:
        driver (WebDriver): Selenium WebDriver instance
        query (str): Search query
        max_results (int): Maximum number of results to return
        
    Returns:
        list: List of dictionaries containing post information
    """
    print(f"Searching Facebook for: {query}")
    log_activity('search', {'platform': 'Facebook', 'query': query})
    
    results = []
    
    try:
        # Navigate to Facebook
        driver.get("https://www.facebook.com")
        time.sleep(random.uniform(2, 4))
        
        # Find and use the search bar
        search_selectors = [
            "//input[@aria-label='Search Facebook']",
            "//input[@placeholder='Search Facebook']",
            "//input[@type='search']",
            "//input[@name='q']"
        ]
        
        search_bar = None
        for selector in search_selectors:
            try:
                search_bar = WebDriverWait(driver, 5).until(
                    EC.element_to_be_clickable((By.XPATH, selector))
                )
                break
            except:
                continue
        
        if not search_bar:
            raise Exception("Could not find Facebook search bar")
        
        search_bar.clear()
        search_bar.send_keys(query)
        search_bar.send_keys(Keys.RETURN)
        
        # Wait for search results to load
        time.sleep(random.uniform(3, 5))
        
        # Click on "Posts" tab to see only posts
        try:
            posts_tab = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, "//span[text()='Posts']"))
            )
            posts_tab.click()
            time.sleep(random.uniform(2, 3))
        except:
            print("Could not find Posts tab, continuing with current results")
        
        # Scroll down to load more content
        for _ in range(3):
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(random.uniform(2, 3))
        
        # Find actual post containers
        post_containers = []
        
        # Try multiple selectors to find actual posts
        selectors_to_try = [
            "//div[@role='article' and @aria-posinset]",
            "//div[@role='feed']//div[@role='article']",
            "//div[contains(@class, 'x1yztbdb') and contains(@class, 'x1n2onr6') and .//a[contains(@href, 'posts')]]",
            "//div[@data-pagelet='FeedUnit']"
        ]
        
        for selector in selectors_to_try:
            try:
                elements = driver.find_elements(By.XPATH, selector)
                if elements:
                    post_containers = elements
                    break
            except:
                continue
        
        print(f"Found {len(post_containers)} potential posts on Facebook")
        
        # Extract information from each post
        for i, post in enumerate(post_containers[:max_results]):
            try:
                post_data = {"index": i+1, "platform": "Facebook"}
                
                # Try to extract the direct post link
                post_link = None
                
                # Method 1: Look for timestamp link
                try:
                    timestamp_link = post.find_element(By.XPATH, ".//a[contains(@role, 'link') and contains(@href, 'posts')]")
                    post_link = timestamp_link.get_attribute("href")
                except:
                    pass
                
                # Method 2: Look for any link containing 'posts'
                if not post_link:
                    try:
                        posts_link = post.find_element(By.XPATH, ".//a[contains(@href, 'posts')]")
                        post_link = posts_link.get_attribute("href")
                    except:
                        pass
                
                # Method 3: Look for share link
                if not post_link:
                    try:
                        share_link = post.find_element(By.XPATH, ".//a[contains(@aria-label, 'Share')]")
                        post_link = share_link.get_attribute("href")
                    except:
                        pass
                
                # Method 4: Get the first link in the post
                if not post_link:
                    try:
                        first_link = post.find_element(By.XPATH, ".//a[contains(@href, 'facebook.com']")
                        post_link = first_link.get_attribute("href")
                    except:
                        pass
                
                post_data["link"] = post_link if post_link else "No link found"
                
                # Try to extract post text
                try:
                    text_element = post.find_element(By.XPATH, ".//div[@data-ad-preview='message']")
                    post_data["text"] = text_element.text[:100] + "..." if len(text_element.text) > 100 else text_element.text
                except:
                    try:
                        text_element = post.find_element(By.XPATH, ".//div[contains(@class, 'x1iorvi4')]")
                        post_data["text"] = text_element.text[:100] + "..." if len(text_element.text) > 100 else text_element.text
                    except:
                        post_data["text"] = "No text available"
                
                # Try to extract author
                try:
                    author_element = post.find_element(By.XPATH, ".//span[contains(@class, 'x1lliihq')]/a")
                    post_data["author"] = author_element.text
                except:
                    try:
                        author_element = post.find_element(By.XPATH, ".//a[@aria-label]/span")
                        post_data["author"] = author_element.text
                    except:
                        post_data["author"] = "Unknown author"
                
                # Try to extract post time
                try:
                    time_element = post.find_element(By.XPATH, ".//a[contains(@aria-label, 'Shared')]")
                    post_data["time"] = time_element.get_attribute("aria-label")
                except:
                    try:
                        time_element = post.find_element(By.XPATH, ".//span[contains(@class, 'x1i10hfl')]/span")
                        post_data["time"] = time_element.text
                    except:
                        post_data["time"] = "Unknown time"
                
                # Add to results with standard format
                results.append({
                    'title': post_data.get("text", "No text available"),
                    'url': post_data.get("link", "No link found"),
                    'snippet': f"Author: {post_data.get('author', 'Unknown')} | Time: {post_data.get('time', 'Unknown')}",
                    'source': 'Facebook',
                    'content': post_data.get("text", "No text available")
                })
                    
            except Exception as e:
                print(f"Error extracting post {i+1}: {str(e)}")
                continue
        
        print(f"Successfully extracted {len(results)} Facebook posts")
        log_activity('search_results', {'platform': 'Facebook', 'count': len(results)})
                    
    except Exception as e:
        print(f"Error scraping Facebook: {str(e)}")
        log_activity('error', {'platform': 'Facebook', 'message': str(e)})
    
    return results

# Instagram Search
def search_instagram(driver, query: str, max_results: int = MAX_RESULTS):
    """
    Searches Instagram for posts related to a query.
    
    Args:
        driver (WebDriver): Selenium WebDriver instance
        query (str): Search query
        max_results (int): Maximum number of results to return
        
    Returns:
        list: List of dictionaries containing post information
    """
    print(f"Searching Instagram for: {query}")
    log_activity('search', {'platform': 'Instagram', 'query': query})
    
    results = []
    
    try:
        # Directly navigate to the hashtag page for more reliable results
        hashtag_url = f"https://www.instagram.com/explore/tags/{query.lower()}/"
        driver.get(hashtag_url)
        time.sleep(random.uniform(3, 5))
        
        # Scroll down to load more content
        for _ in range(3):
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(random.uniform(2, 3))
        
        # Find all post links in the hashtag page
        post_links = []
        
        # Try multiple selectors to find post links
        link_selectors = [
            "//a[contains(@href, '/p/')]",
            "//a[contains(@href, '/reel/')",
            "//article//a[contains(@href, '/')]"
        ]
        
        for selector in link_selectors:
            try:
                links = driver.find_elements(By.XPATH, selector)
                if links:
                    post_links.extend(links)
                    break
            except:
                continue
        
        # Remove duplicates and get unique links
        unique_links = []
        seen_hrefs = set()
        
        for link in post_links:
            href = link.get_attribute("href")
            if href and href not in seen_hrefs and ('/p/' in href or '/reel/' in href):
                unique_links.append(href)
                seen_hrefs.add(href)
        
        print(f"Found {len(unique_links)} unique posts on Instagram")
        
        # Extract information for top posts
        for i, link in enumerate(unique_links[:max_results]):
            try:
                post_data = {
                    "index": i+1,
                    "platform": "Instagram",
                    "link": link
                }
                
                # Try to get additional info without opening the post
                try:
                    # Find the corresponding element to get more info
                    post_element = driver.find_element(By.XPATH, f"//a[@href='{link}']")
                    
                    # Try to get image alt text
                    try:
                        img_element = post_element.find_element(By.XPATH, ".//img")
                        post_data["image_alt"] = img_element.get_attribute("alt")
                    except:
                        pass
                    
                    # Try to get like count (if visible)
                    try:
                        like_element = post_element.find_element(By.XPATH, ".//span[contains(text(), 'likes')]")
                        post_data["likes"] = like_element.text
                    except:
                        pass
                    
                except:
                    pass
                
                # Add to results with standard format
                results.append({
                    'title': post_data.get("image_alt", "Instagram post"),
                    'url': post_data.get("link", "No link found"),
                    'snippet': f"Likes: {post_data.get('likes', 'Unknown')}",
                    'source': 'Instagram',
                    'content': post_data.get("image_alt", "No text available")
                })
                    
            except Exception as e:
                print(f"Error extracting post {i+1}: {str(e)}")
                continue
        
        print(f"Successfully extracted {len(results)} Instagram posts")
        log_activity('search_results', {'platform': 'Instagram', 'count': len(results)})
            
    except Exception as e:
        print(f"Error scraping Instagram: {str(e)}")
        log_activity('error', {'platform': 'Instagram', 'message': str(e)})
    
    return results

# Enhanced WHOIS Check with Red Flag Analysis
@st.cache_data(ttl=3600)  # Cache for 1 hour
def check_whois_with_analysis(domains: List[str]) -> Dict:
    """
    Checks the WHOIS information for domains and analyzes them against red flags.
    
    Args:
        domains (List[str]): List of domain names to check
        
    Returns:
        Dict: WHOIS information and red flag analysis for all domains
    """
    if not domains:
        return {
            "error": "No domains found in content to analyze",
            "domains": []
        }
    
    print(f"Checking WHOIS for {len(domains)} domains")
    log_activity('whois_check', {'domains': domains})
    
    results = {
        "domains": [],
        "highest_risk": "Minimal",
        "highest_risk_score": 0
    }
    
    try:
        # Get API key from environment variables
        api_key = os.getenv("WHOIS_API_KEY")
        if not api_key:
            return {
                "error": "WHOIS API key not configured. Please add it to your .env file or enter it in the sidebar."
            }
        
        for domain in domains:
            try:
                # Ensure domain is in the right format
                if domain.startswith("http"):
                    from urllib.parse import urlparse
                    parsed_url = urlparse(domain)
                    domain_name = parsed_url.netloc
                else:
                    domain_name = domain
                
                # Remove www. if present
                if domain_name.startswith("www."):
                    domain_name = domain_name[4:]
                
                url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain_name}&outputFormat=JSON"
                
                response = requests.get(url)
                data = response.json()
                
                # Extract WHOIS data
                whois_data = {
                    "domain": data.get('WhoisRecord', {}).get('domainName', domain_name),
                    "registrar": data.get('WhoisRecord', {}).get('registrarName', 'Not available'),
                    "registrant": data.get('WhoisRecord', {}).get('registrant', {}).get('organization', 'Not available'),
                    "creation_date": data.get('WhoisRecord', {}).get('createdDate', 'Not available'),
                    "expiration_date": data.get('WhoisRecord', {}).get('expiresDate', 'Not available'),
                    "name_servers": data.get('WhoisRecord', {}).get('nameServers', {}).get('hostNames', 'Not available')
                }
                
                # Analyze for red flags
                red_flags = []
                risk_score = 0
                
                # Flag 1 (High Priority): Check creation date
                creation_date_str = whois_data.get('creation_date', 'Not available')
                if creation_date_str != 'Not available':
                    try:
                        # Parse the creation date
                        if isinstance(creation_date_str, list):
                            creation_date_str = creation_date_str[0]
                        
                        # Handle different date formats
                        if 'T' in creation_date_str:
                            creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
                        else:
                            creation_date = datetime.strptime(creation_date_str.split(' ')[0], '%Y-%m-%d')
                        
                        # Calculate days since creation
                        days_since_creation = (CURRENT_DATE - creation_date.replace(tzinfo=None)).days
                        
                        if days_since_creation <= 180:
                            red_flags.append({
                                "flag": "New Domain",
                                "priority": "High",
                                "description": f"Domain created only {days_since_creation} days ago (within the last 180 days)"
                            })
                            risk_score += 30
                    except Exception as e:
                        print(f"Error parsing creation date: {e}")
                
                # Flag 2 (Medium Priority): Check registrant information for privacy protection
                registrant_info = whois_data.get('registrant', 'Not available')
                if registrant_info != 'Not available':
                    for keyword in PRIVACY_KEYWORDS:
                        if keyword.lower() in str(registrant_info).lower():
                            red_flags.append({
                                "flag": "Hidden Identity",
                                "priority": "Medium",
                                "description": f"Registrant information contains privacy protection keyword: '{keyword}'"
                            })
                            risk_score += 20
                            break
                
                # Flag 3 (Low Priority): Check TLD
                domain_name = whois_data.get('domain', '')
                for tld in HIGH_RISK_TLDS:
                    if domain_name.lower().endswith(tld):
                        red_flags.append({
                            "flag": "High-Risk TLD",
                            "priority": "Low",
                            "description": f"Domain uses high-risk TLD: {tld}"
                        })
                        risk_score += 10
                        break
                
                # Determine overall risk level
                if risk_score >= 30:
                    risk_level = "High"
                elif risk_score >= 20:
                    risk_level = "Medium"
                elif risk_score >= 10:
                    risk_level = "Low"
                else:
                    risk_level = "Minimal"
                
                domain_result = {
                    "domain": domain_name,
                    "whois_data": whois_data,
                    "red_flags": red_flags,
                    "risk_score": risk_score,
                    "risk_level": risk_level
                }
                
                results["domains"].append(domain_result)
                
                # Update highest risk if needed
                if risk_score > results["highest_risk_score"]:
                    results["highest_risk_score"] = risk_score
                    results["highest_risk"] = risk_level
                
                log_activity('whois_result', {'domain': domain_name, 'risk_level': risk_level, 'risk_score': risk_score})
                
            except Exception as e:
                error_result = {
                    "domain": domain,
                    "error": f"Error checking WHOIS: {str(e)}",
                    "whois_data": {},
                    "red_flags": [],
                    "risk_score": 0,
                    "risk_level": "Unknown"
                }
                results["domains"].append(error_result)
                log_activity('error', {'type': 'whois', 'domain': domain, 'message': str(e)})
        
        return results
        
    except Exception as e:
        error_result = {
            "error": f"Error in WHOIS analysis: {str(e)}",
            "domains": domains
        }
        log_activity('error', {'type': 'whois', 'message': str(e)})
        return error_result

# Location Verification for Hotel-Related Websites
@st.cache_data(ttl=3600)  # Cache for 1 hour
def verify_hotel_location(url: str, title: str, description: str) -> Dict:
    """
    Verifies if a hotel-related website corresponds to a real location using Google Maps API.
    
    Args:
        url (str): Website URL
        title (str): Website title
        description (str): Website description
        
    Returns:
        Dict: Location verification results
    """
    print(f"Verifying hotel location for: {title}")
    log_activity('location_verification', {'url': url, 'title': title})
    
    try:
        # Get API key from environment variables
        api_key = os.getenv("GOOGLE_MAPS_API_KEY")
        if not api_key:
            return {
                "verified": False,
                "error": "Google Maps API key not configured"
            }
        
        # Check if the content is hotel-related
        hotel_keywords = ['hotel', 'resort', 'stay', 'accommodation', 'booking', 'motel', 'inn', 'lodging']
        content = f"{title} {description}".lower()
        
        is_hotel_related = any(keyword in content for keyword in hotel_keywords)
        
        if not is_hotel_related:
            result = {
                "verified": False,
                "reason": "Content is not hotel-related",
                "is_hotel_related": False
            }
            log_activity('location_result', {'url': url, 'verified': False, 'reason': 'Not hotel-related'})
            return result
        
        # Extract potential location names from title and description
        # This is a simplified approach - in a real implementation, you might use NLP
        location_candidates = []
        
        # Try to extract location from title (common pattern: "Hotel Name - Location")
        if '-' in title:
            parts = title.split('-')
            if len(parts) >= 2:
                location_candidates.append(parts[-1].strip())
        
        # Add title itself as a candidate
        location_candidates.append(title)
        
        # Try to extract from description (look for address patterns)
        address_pattern = r'\d+\s+[\w\s]+,\s*[\w\s]+,\s*[\w\s]+,\s*\w{2}\s*\d{5}'
        addresses = re.findall(address_pattern, description)
        location_candidates.extend(addresses)
        
        # Try each candidate with Google Places API
        for location in location_candidates:
            try:
                # Use Google Places Text Search
                places_url = f"https://maps.googleapis.com/maps/api/place/textsearch/json"
                params = {
                    'query': location,
                    'type': 'lodging',
                    'key': api_key
                }
                
                response = requests.get(places_url, params=params)
                places_data = response.json()
                
                if places_data.get('status') == 'OK' and places_data.get('results'):
                    # We found at least one matching place
                    place = places_data['results'][0]
                    
                    # Get place details for more information
                    place_id = place.get('place_id')
                    if place_id:
                        details_url = "https://maps.googleapis.com/maps/api/place/details/json"
                        details_params = {
                            'place_id': place_id,
                            'fields': 'name,formatted_address,website,rating,photos',
                            'key': api_key
                        }
                        
                        details_response = requests.get(details_url, params=details_params)
                        details_data = details_response.json()
                        
                        if details_data.get('status') == 'OK':
                            place_details = details_data.get('result', {})
                            
                            # Check if the website matches
                            website = place_details.get('website', '')
                            if website and url in website:
                                result = {
                                    "verified": True,
                                    "place_name": place_details.get('name', ''),
                                    "address": place_details.get('formatted_address', ''),
                                    "rating": place_details.get('rating', 0),
                                    "website": website,
                                    "photos": place_details.get('photos', []),
                                    "is_hotel_related": True
                                }
                                log_activity('location_result', {'url': url, 'verified': True, 'place_name': result['place_name']})
                                return result
                            else:
                                result = {
                                    "verified": False,
                                    "reason": "Found matching location but website doesn't match",
                                    "place_name": place_details.get('name', ''),
                                    "address": place_details.get('formatted_address', ''),
                                    "is_hotel_related": True
                                }
                                log_activity('location_result', {'url': url, 'verified': False, 'reason': result['reason']})
                                return result
            except Exception as e:
                print(f"Error checking location '{location}': {e}")
                continue
        
        # If we get here, we couldn't verify the location
        result = {
            "verified": False,
            "reason": "Could not find matching location in Google Places",
            "is_hotel_related": True
        }
        log_activity('location_result', {'url': url, 'verified': False, 'reason': result['reason']})
        return result
        
    except Exception as e:
        error_result = {
            "verified": False,
            "error": f"Error verifying location: {str(e)}",
            "is_hotel_related": False
        }
        log_activity('error', {'type': 'location_verification', 'url': url, 'message': str(e)})
        return error_result

# Enhanced Gemini AI Analysis with Keyword Matching
def analyze_content_with_gemini(content: str, source: str, url: str, fraud_keywords: Dict, fraudulent_activities: Dict) -> Dict:
    """
    Analyzes content using Gemini AI to detect potential scams and cross-references with fraud keywords.
    
    Args:
        content (str): Content to analyze
        source (str): Source of the content (Google, YouTube, etc.)
        url (str): URL of the content
        fraud_keywords (Dict): Dictionary of fraud keywords by category
        fraudulent_activities (Dict): Dictionary of fraudulent activity keywords
        
    Returns:
        Dict: Analysis results
    """
    print(f"Analyzing content from {source}: {content[:50]}...")
    log_activity('content_analysis', {'source': source, 'url': url})
    
    try:
        # First, check against fraud keywords
        keyword_matches = check_fraud_keywords(content, fraud_keywords, fraudulent_activities)
        
        # Initialize result with keyword analysis
        result = {
            "is_scam": False,
            "confidence_score": 0.0,
            "reason": "",
            "scam_type": "Unknown",
            "keyword_matches": keyword_matches
        }
        
        # If we have high keyword match score, it's likely a scam
        if keyword_matches['risk_score'] >= 20:
            result['is_scam'] = True
            result['confidence_score'] = min(0.9, 0.5 + (keyword_matches['risk_score'] / 100))
            result['reason'] = " | ".join(keyword_matches['reasons'][:3])  # Top 3 reasons
            
            # Determine scam type based on categories
            if 'financial' in keyword_matches['categories']:
                result['scam_type'] = 'Financial Fraud'
            elif 'credit_card_identity' in keyword_matches['categories']:
                result['scam_type'] = 'Credit Card/Identity Fraud'
            elif 'email_phishing' in keyword_matches['categories']:
                result['scam_type'] = 'Email/Phishing Fraud'
            elif 'prostitution' in keyword_matches['categories']:
                result['scam_type'] = 'Prostitution'
            elif 'gambling' in keyword_matches['categories']:
                result['scam_type'] = 'Gambling'
            elif 'investment_groups' in keyword_matches.get('activities', {}):
                result['scam_type'] = 'Investment Scam'
            elif 'fake_hotels' in keyword_matches.get('activities', {}):
                result['scam_type'] = 'Fake Hotel'
            else:
                result['scam_type'] = 'General Fraud'
            
            log_activity('scam_detected', {
                'source': source, 
                'url': url, 
                'scam_type': result['scam_type'],
                'confidence': result['confidence_score'],
                'method': 'keyword_matching'
            })
            
            return result
        
        # If keyword matching is inconclusive, use Gemini AI
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            result['reason'] = "Gemini API key not configured"
            log_activity('error', {'type': 'gemini', 'message': 'API key not configured'})
            return result
            
        genai.configure(api_key=api_key)
        
        model_names = ['gemini-2.5-flash']
        model = None
        
        for model_name in model_names:
            try:
                model = genai.GenerativeModel(model_name)
                break
            except Exception:
                continue
                
        if not model:
            result['reason'] = "No compatible Gemini model available"
            log_activity('error', {'type': 'gemini', 'message': 'No compatible model'})
            return result
        
        # Include keyword matches in the prompt for context
        keyword_context = ""
        if keyword_matches['keywords']:
            keyword_context = f"\n\nThe following suspicious keywords were found in the content: {', '.join(keyword_matches['keywords'][:5])}"
        
        prompt = f"""
        Act as a highly critical financial and security analyst. Your task is to analyze the following text from {source} and determine if it exhibits characteristics of a scam.
        
        Analyze based on these scam indicators:
        - **Urgency & Scarcity:** "Act now," "limited time offer," "only 3 spots left."
        - **Guaranteed High Returns:** "Guaranteed profit," "risk-free," "double your money in 24 hours."
        - **Vague Technical Jargon:** Using complex terms without clear explanation to sound legitimate.
        - **Pressure to Recruit Others:** Mention of downlines, recruitment bonuses, or multi-level marketing (MLM) structures.
        - **Request for Personal Info/Wallet Keys:** "Enter your seed phrase," "give us remote access," "verify your wallet."
        - **Social Proof Manipulation:** Mentioning celebrity endorsements that are likely fake.
        - **Platform Diversion:** Pushing users to leave {source} for unregulated platforms like Telegram or WhatsApp.
        
        Text to Analyze:
        ---
        {content}
        ---
        {keyword_context}
        
        Based on your analysis, provide your response strictly in the following JSON format. Do not add any other text or explanation outside of this JSON structure.
        
        {{
          "is_scam": boolean,
          "confidence_score": float,
          "reason": "A brief explanation for your decision, citing specific keywords or phrases from the text.",
          "scam_type": "Classify the potential scam (e.g., 'Phishing', 'Ponzi Scheme', 'Crypto Pump & Dump', 'MLM', 'Unrealistic Investment')"
        }}
        """
        
        # Implement retry logic with exponential backoff
        max_retries = 3
        base_delay = 6  # Start with 6 seconds delay to stay within rate limits
        
        for attempt in range(max_retries):
            try:
                response = model.generate_content(prompt)
                response_text = response.text
                
                try:
                    if "```json" in response_text:
                        response_text = response_text.split("```json")[1].split("```")[0]
                    elif "```" in response_text:
                        response_text = response_text.split("```")[1].split("```")[0]
                        
                    analysis_result = json.loads(response_text)
                    
                    required_fields = ["is_scam", "confidence_score", "reason", "scam_type"]
                    for field in required_fields:
                        if field not in analysis_result:
                            raise ValueError(f"Missing required field: {field}")
                    
                    # Combine with keyword analysis
                    if keyword_matches['risk_score'] > 0:
                        # Boost confidence if keywords were found
                        analysis_result['confidence_score'] = min(0.95, analysis_result['confidence_score'] + (keyword_matches['risk_score'] / 200))
                        
                        # Add keyword reasons to the analysis reason
                        if keyword_matches['reasons']:
                            analysis_result['reason'] += f" | Keyword indicators: {' | '.join(keyword_matches['reasons'][:2])}"
                    
                    analysis_result['keyword_matches'] = keyword_matches
                    
                    if analysis_result['is_scam']:
                        log_activity('scam_detected', {
                            'source': source, 
                            'url': url, 
                            'scam_type': analysis_result['scam_type'],
                            'confidence': analysis_result['confidence_score'],
                            'method': 'gemini_analysis'
                        })
                    
                    return analysis_result
                except (json.JSONDecodeError, ValueError) as e:
                    result['reason'] = f"Failed to parse Gemini response: {str(e)}"
                    log_activity('error', {'type': 'gemini_parsing', 'message': str(e)})
                    return result
            
            except Exception as e:
                if "429" in str(e) and attempt < max_retries - 1:
                    # Rate limit error, wait and retry
                    delay = base_delay * (2 ** attempt)  # Exponential backoff
                    st.warning(f"Rate limit reached. Waiting {delay} seconds before retrying...")
                    time.sleep(delay)
                else:
                    # Non-rate limit error or max retries reached
                    result['reason'] = f"Analysis failed: {str(e)}"
                    log_activity('error', {'type': 'gemini', 'message': str(e)})
                    return result
            
            # Add a delay between requests to avoid hitting rate limits
            if attempt < max_retries - 1:
                time.sleep(6)  # 6 seconds delay to stay within the 10 requests/minute limit
            
    except Exception as e:
        result['reason'] = f"Analysis failed: {str(e)}"
        log_activity('error', {'type': 'gemini', 'message': str(e)})
        return result

# Process search
if search_button or (search_query and st.session_state.get('last_query') != search_query):
    if not search_query:
        st.warning("Please enter a search query")
    else:
        with st.spinner("Searching and analyzing content..."):
            # Load fraud keywords
            fraud_keywords, fraudulent_activities = load_fraud_keywords()
            
            # Initialize Chrome driver
            driver = initialize_driver()
            
            try:
                # Get date range from session state
                start_date, end_date = st.session_state.date_range
                
                # Search Google
                google_results = search_google(driver, search_query, date_range=(start_date, end_date))
                
                # Search YouTube
                youtube_results = search_youtube_videos(search_query, date_range=(start_date, end_date))
                
                # Search Facebook
                facebook_results = search_facebook(driver, search_query)
                
                # Search Instagram
                instagram_results = search_instagram(driver, search_query)
                
                # Combine all results
                all_results = google_results + youtube_results + facebook_results + instagram_results
                
                if not all_results:
                    st.error("No results found or error occurred during search")
                else:
                    # Create a progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    results = []
                    for i, result in enumerate(all_results):
                        # Update progress
                        progress = (i + 1) / len(all_results)
                        progress_bar.progress(progress)
                        status_text.text(f"Analyzing result {i+1}/{len(all_results)}: {result['title'][:50]}...")
                        
                        # Get textual corpus
                        if result['source'] == 'YouTube':
                            content = f"Title: {result['title']}\n\nDescription: {result['description']}"
                        else:
                            content = f"Title: {result['title']}\n\nDescription: {result['snippet']}"
                        
                        # Analyze with Gemini and keyword matching
                        analysis = analyze_content_with_gemini(
                            content, 
                            result['source'], 
                            result['url'],
                            fraud_keywords,
                            fraudulent_activities
                        )
                        
                        # Extract domains from content for WHOIS analysis
                        domains = extract_domains_from_content(content)
                        whois_info = {}
                        if domains:
                            whois_info = check_whois_with_analysis(domains)
                        
                        # ScamAdviser-like analysis for Google search results
                        scamadviser_analysis = {}
                        if result['source'] == 'Google' and result['url'] != "No URL found":
                            scamadviser_analysis = analyze_website_like_scamadviser(
                                result['url'], 
                                result['title'], 
                                result['snippet']
                            )
                        
                        # Threat Intelligence Analysis
                        threat_analysis = threat_intelligence_analysis(
                            content,
                            result['source'],
                            result['url'],
                            analysis.get('keyword_matches', {})
                        )
                        
                        # Verify location for hotel-related websites
                        location_verification = {}
                        if result['source'] == 'Google' and result['url'] != "No URL found":
                            title = result['title']
                            description = result['snippet']
                            location_verification = verify_hotel_location(result['url'], title, description)
                        
                        # Store results
                        result_item = {
                            'result': result,
                            'analysis': analysis,
                            'whois': whois_info,
                            'scamadviser': scamadviser_analysis,
                            'threat_intelligence': threat_analysis,
                            'location_verification': location_verification,
                            'extracted_domains': domains
                        }
                        results.append(result_item)
                    
                    # Clear progress indicators
                    progress_bar.empty()
                    status_text.empty()
                    
                    # Sort results by scam likelihood (highest first)
                    sorted_results = sorted(results, key=lambda x: x['analysis'].get('confidence_score', 0), reverse=True)
                    
                    # Update session state
                    st.session_state.results = sorted_results
                    st.session_state.last_query = search_query
                    
                    st.success(f"Analyzed {len(sorted_results)} results")
            finally:
                # Always close the driver
                driver.quit()

# Display results
if st.session_state.results:
    st.header("Analysis Results")
    
    # Create a DataFrame for easier manipulation
    df_data = []
    for result in st.session_state.results:
        item = result['result']
        analysis = result['analysis']
        whois_info = result['whois']
        scamadviser_analysis = result.get('scamadviser', {})
        threat_analysis = result.get('threat_intelligence', {})
        location_verification = result['location_verification']
        extracted_domains = result.get('extracted_domains', [])
        
        # Calculate overall risk score
        risk_score = analysis.get('confidence_score', 0) * 100
        
        # Add WHOIS risk score if available
        if 'highest_risk_score' in whois_info:
            risk_score += whois_info['highest_risk_score']
        
        # Add ScamAdviser risk score if available
        if 'trust_score' in scamadviser_analysis:
            # Convert ScamAdviser trust score to risk score (inverse relationship)
            scamadviser_risk = 100 - scamadviser_analysis['trust_score']
            risk_score += scamadviser_risk * 0.5  # Weight ScamAdviser score less than other factors
        
        # Add Threat Intelligence risk score if available
        if 'risk_score' in threat_analysis:
            risk_score += threat_analysis['risk_score'] * 0.7  # Weight threat intelligence score highly
        
        # Add keyword match risk score if available
        if 'keyword_matches' in analysis and 'risk_score' in analysis['keyword_matches']:
            risk_score += analysis['keyword_matches']['risk_score']
        
        # Determine if location is verified for hotel-related sites
        location_verified = location_verification.get('verified', False)
        is_hotel_related = location_verification.get('is_hotel_related', False)
        
        df_data.append({
            'Title': item['title'],
            'URL': item['url'],
            'Source': item['source'],
            'Is Scam': 'Yes' if analysis.get('is_scam', False) or threat_analysis.get('is_scam', False) else 'No',
            'Confidence Score': max(analysis.get('confidence_score', 0.0), threat_analysis.get('confidence', 0.0)),
            'Scam Type': threat_analysis.get('scam_type', analysis.get('scam_type', 'Unknown')),
            'WHOIS Risk': whois_info.get('highest_risk', 'Unknown'),
            'ScamAdviser Score': scamadviser_analysis.get('trust_score', 'N/A'),
            'ScamAdviser Verdict': scamadviser_analysis.get('final_verdict', 'Unknown'),
            'Threat Risk Score': threat_analysis.get('risk_score', 'N/A'),
            'Location Verified': 'Yes' if location_verified else 'No' if is_hotel_related else 'N/A',
            'Overall Risk Score': risk_score,
            'Domains Found': len(extracted_domains)
        })
    
    df = pd.DataFrame(df_data)
    
    # Display summary statistics
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    
    with col1:
        total_results = len(df)
        st.metric("Total Results Analyzed", total_results)
    
    with col2:
        scam_count = df['Is Scam'].value_counts().get('Yes', 0)
        st.metric("Potential Scams", scam_count)
    
    with col3:
        high_risk_count = df[df['WHOIS Risk'] == 'High'].shape[0]
        st.metric("High Risk Domains", high_risk_count)
    
    with col4:
        fraudulent_sites = df[df['ScamAdviser Verdict'] == 'Fraudulent'].shape[0]
        st.metric("Fraudulent Sites", fraudulent_sites)
    
    with col5:
        high_threat_risk = df[df['Threat Risk Score'] >= 70].shape[0]
        st.metric("High Threat Risk", high_threat_risk)
    
    with col6:
        verified_locations = df[df['Location Verified'] == 'Yes'].shape[0]
        st.metric("Verified Locations", verified_locations)
    
    # Display results in tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["Detailed Results", "Summary Table", "WHOIS Analysis", "ScamAdviser Analysis", "Threat Intelligence", "Location Verification", "Activity Logs"])
    
    with tab1:
        for i, result in enumerate(st.session_state.results):
            item = result['result']
            analysis = result['analysis']
            whois_info = result['whois']
            scamadviser_analysis = result.get('scamadviser', {})
            threat_analysis = result.get('threat_intelligence', {})
            location_verification = result['location_verification']
            extracted_domains = result.get('extracted_domains', [])
            
            is_scam = analysis.get('is_scam', False) or threat_analysis.get('is_scam', False)
            confidence_score = max(analysis.get('confidence_score', 0.0), threat_analysis.get('confidence', 0.0))
            scam_type = threat_analysis.get('scam_type', analysis.get('scam_type', 'Unknown'))
            reason = analysis.get('reason', 'No reason provided')
            
            # Keyword matches
            keyword_matches = analysis.get('keyword_matches', {})
            matched_keywords = keyword_matches.get('keywords', [])
            matched_categories = keyword_matches.get('categories', {})
            matched_activities = keyword_matches.get('activities', {})
            
            # WHOIS information
            whois_risk_level = whois_info.get('highest_risk', 'Unknown')
            
            # ScamAdviser information
            scamadviser_verdict = scamadviser_analysis.get('final_verdict', 'Unknown')
            scamadviser_trust_score = scamadviser_analysis.get('trust_score', 'N/A')
            scamadviser_recommendation = scamadviser_analysis.get('recommendation', 'Unknown')
            
            # Threat Intelligence information
            threat_risk_score = threat_analysis.get('risk_score', 'N/A')
            threat_summary = threat_analysis.get('summary', 'No summary available')
            threat_reasoning = threat_analysis.get('reasoning', 'No reasoning available')
            threat_red_flags = threat_analysis.get('red_flags', [])
            
            # Location verification
            location_verified = location_verification.get('verified', False)
            is_hotel_related = location_verification.get('is_hotel_related', False)
            
            # Create a card for each result
            with st.container():
                st.markdown("---")
                
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.markdown(f"### {item['title']}")
                    st.markdown(f"[View on {item['source']}]({item['url']})")
                    
                    if item['source'] == 'YouTube':
                        st.markdown(f"**Description:** {item['description'][:200]}{'...' if len(item['description']) > 200 else ''}")
                    else:
                        st.markdown(f"**Description:** {item['snippet'][:200]}{'...' if len(item['snippet']) > 200 else ''}")
                
                with col2:
                    if is_scam:
                        st.error("POTENTIAL SCAM")
                    else:
                        st.success("LIKELY SAFE")
                    
                    st.metric("Confidence", f"{confidence_score:.2f}")
                    st.caption(f"Type: {scam_type}")
                    
                    # WHOIS risk indicator
                    if whois_risk_level == 'High':
                        st.error(f"WHOIS Risk: {whois_risk_level}")
                    elif whois_risk_level == 'Medium':
                        st.warning(f"WHOIS Risk: {whois_risk_level}")
                    elif whois_risk_level == 'Low':
                        st.info(f"WHOIS Risk: {whois_risk_level}")
                    else:
                        st.caption(f"WHOIS Risk: {whois_risk_level}")
                    
                    # ScamAdviser verdict indicator
                    if scamadviser_verdict == 'Legitimate':
                        st.success(f"ScamAdviser: {scamadviser_verdict}")
                    elif scamadviser_verdict == 'Suspicious':
                        st.warning(f"ScamAdviser: {scamadviser_verdict}")
                    elif scamadviser_verdict == 'Fraudulent':
                        st.error(f"ScamAdviser: {scamadviser_verdict}")
                    else:
                        st.caption(f"ScamAdviser: {scamadviser_verdict}")
                    
                    # Threat Intelligence risk indicator
                    if isinstance(threat_risk_score, (int, float)):
                        if threat_risk_score >= 70:
                            st.error(f"Threat Risk: {threat_risk_score}")
                        elif threat_risk_score >= 40:
                            st.warning(f"Threat Risk: {threat_risk_score}")
                        else:
                            st.info(f"Threat Risk: {threat_risk_score}")
                    else:
                        st.caption(f"Threat Risk: {threat_risk_score}")
                    
                    # Location verification indicator
                    if is_hotel_related:
                        if location_verified:
                            st.success("Location Verified")
                        else:
                            st.error("Location Not Verified")
                
                st.markdown(f"**Analysis:** {reason}")
                
                # User feedback buttons
                col1, col2, col3 = st.columns([1, 1, 1])
                with col1:
                    if st.button(f"👍 Correct", key=f"correct_{i}"):
                        # Get content for feedback
                        if item['source'] == 'YouTube':
                            content = f"Title: {item['title']}\n\nDescription: {item['description']}"
                        else:
                            content = f"Title: {item['title']}\n\nDescription: {item['snippet']}"
                        
                        # Save feedback
                        save_feedback(
                            content, 
                            "scam" if is_scam else "safe", 
                            "scam" if is_scam else "safe", 
                            item['source'], 
                            item['url']
                        )
                        st.success("Feedback saved! Thank you for helping improve the system.")
                
                with col2:
                    if st.button(f"👎 Incorrect", key=f"incorrect_{i}"):
                        # Get content for feedback
                        if item['source'] == 'YouTube':
                            content = f"Title: {item['title']}\n\nDescription: {item['description']}"
                        else:
                            content = f"Title: {item['title']}\n\nDescription: {item['snippet']}"
                        
                        # Save feedback with corrected label
                        save_feedback(
                            content, 
                            "scam" if is_scam else "safe", 
                            "safe" if is_scam else "scam", 
                            item['source'], 
                            item['url']
                        )
                        st.success("Feedback saved! Thank you for helping improve the system.")
                
                with col3:
                    if st.button(f"📊 Details", key=f"details_{i}"):
                        # This button could expand to show more detailed analysis
                        pass
                
                # Show Threat Intelligence analysis if available
                if threat_analysis:
                    st.markdown("**Threat Intelligence Analysis:**")
                    st.markdown(f"**Summary:** {threat_summary}")
                    st.markdown(f"**Risk Score:** {threat_risk_score}")
                    
                    # Show red flags
                    if threat_red_flags:
                        st.markdown("**Red Flags:**")
                        for flag in threat_red_flags:
                            st.markdown(f"- **{flag.get('flag', 'Unknown')}**: {flag.get('evidence', 'No evidence')}")
                    
                    # Show reasoning (collapsible to save space)
                    with st.expander("View Detailed Reasoning"):
                        st.markdown(threat_reasoning)
                
                # Show ScamAdviser analysis if available
                if scamadviser_analysis and item['source'] == 'Google':
                    st.markdown("**ScamAdviser Analysis:**")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Trust Score", scamadviser_trust_score)
                    with col2:
                        st.metric("Verdict", scamadviser_verdict)
                    with col3:
                        st.caption(f"Recommendation: {scamadviser_recommendation}")
                
                # Show extracted domains if any
                if extracted_domains:
                    st.markdown("**Extracted Domains:**")
                    st.write(", ".join(extracted_domains[:10]))  # Show first 10
                
                # Show matched keywords if any
                if matched_keywords:
                    st.markdown("**Matched Fraud Keywords:**")
                    st.write(", ".join(matched_keywords[:10]))  # Show first 10
                
                # Show matched categories if any
                if matched_categories:
                    st.markdown("**Fraud Categories:**")
                    for category, keywords in matched_categories.items():
                        st.markdown(f"- {category.replace('_', ' ').title()}: {', '.join(keywords[:5])}")
                
                # Show matched activities if any
                if matched_activities:
                    st.markdown("**Fraudulent Activities:**")
                    for activity, keywords in matched_activities.items():
                        st.markdown(f"- {activity.replace('_', ' ').title()}: {', '.join(keywords[:5])}")
                
                # Show location verification details if applicable
                if is_hotel_related:
                    if location_verified:
                        st.markdown("**Location Verification Details:**")
                        st.markdown(f"- Place Name: {location_verification.get('place_name', 'Unknown')}")
                        st.markdown(f"- Address: {location_verification.get('address', 'Unknown')}")
                        st.markdown(f"- Rating: {location_verification.get('rating', 'N/A')}")
                    else:
                        st.markdown(f"**Location Verification:** {location_verification.get('reason', 'Unknown')}")
    
    with tab2:
        # Format the DataFrame for display
        display_df = df.copy()
        display_df['URL'] = display_df['URL'].apply(lambda x: f"[View]({x})")
        
        # Display the table
        st.dataframe(display_df, use_container_width=True)
        
        # Download button
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download Results as CSV",
            data=csv,
            file_name=f"threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    with tab3:
        # Display WHOIS information for extracted domains
        results_with_domains = [r for r in st.session_state.results if r.get('extracted_domains')]
        
        if results_with_domains:
            for result in results_with_domains:
                item = result['result']
                whois_info = result['whois']
                extracted_domains = result.get('extracted_domains', [])
                
                with st.expander(f"WHOIS Analysis for domains in: {item['title'][:50]}..."):
                    if 'error' in whois_info:
                        st.error(whois_info['error'])
                    else:
                        # Display extracted domains
                        st.markdown(f"**Extracted Domains ({len(extracted_domains)}):**")
                        st.write(", ".join(extracted_domains))
                        
                        # Display domain analysis results
                        if 'domains' in whois_info:
                            for domain_result in whois_info['domains']:
                                if 'error' in domain_result:
                                    st.error(f"Error for {domain_result.get('domain', 'Unknown')}: {domain_result['error']}")
                                else:
                                    st.markdown(f"**Domain:** {domain_result.get('domain', 'Unknown')}")
                                    st.markdown(f"**Risk Level:** {domain_result.get('risk_level', 'Unknown')}")
                                    st.markdown(f"**Risk Score:** {domain_result.get('risk_score', 0)}")
                                    
                                    st.markdown("---")
        else:
            st.info("No domains found in content for WHOIS analysis.")
    
    with tab4:
        # Display ScamAdviser analysis for Google search results
        google_results = [r for r in st.session_state.results if r['result']['source'] == 'Google' and r.get('scamadviser')]
        
        if google_results:
            for result in google_results:
                item = result['result']
                scamadviser_analysis = result.get('scamadviser', {})
                
                with st.expander(f"ScamAdviser Analysis for: {item['title'][:50]}..."):
                    if 'error' in scamadviser_analysis:
                        st.error(scamadviser_analysis['error'])
                    else:
                        # Display key metrics
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Trust Score", scamadviser_analysis.get('trust_score', 'N/A'))
                        with col2:
                            st.metric("Verdict", scamadviser_analysis.get('final_verdict', 'Unknown'))
                        with col3:
                            st.metric("Confidence", f"{scamadviser_analysis.get('confidence_score', 0):.2f}")
                            
                        # Display domain information
                        st.markdown("**Domain Information:**")
                        st.markdown(f"- URL: {scamadviser_analysis.get('url', 'Unknown')}")
                        st.markdown(f"- Domain: {scamadviser_analysis.get('domain', 'Unknown')}")
                        st.markdown(f"- Domain Age: {scamadviser_analysis.get('domain_age', 'Unknown')}")
                        st.markdown(f"- SSL Certificate: {scamadviser_analysis.get('ssl_certificate', 'Unknown')}")
                        st.markdown(f"- Server Location: {scamadviser_analysis.get('server_location', 'Unknown')}")
                        
                        # Display content red flags
                        if 'content_red_flags' in scamadviser_analysis and scamadviser_analysis['content_red_flags']:
                            st.markdown("**Content Red Flags:**")
                            for flag in scamadviser_analysis['content_red_flags']:
                                st.markdown(f"- {flag}")
                        
                        # Display recommendation
                        st.markdown(f"**Recommendation:** {scamadviser_analysis.get('recommendation', 'Unknown')}")
        else:
            st.info("No ScamAdviser analysis available. This feature only works for Google search results.")
    
    with tab5:
        # Display Threat Intelligence analysis
        results_with_threat_analysis = [r for r in st.session_state.results if r.get('threat_intelligence')]
        
        if results_with_threat_analysis:
            for result in results_with_threat_analysis:
                item = result['result']
                threat_analysis = result.get('threat_intelligence', {})
                
                with st.expander(f"Threat Intelligence Analysis for: {item['title'][:50]}..."):
                    if 'error' in threat_analysis:
                        st.error(threat_analysis['error'])
                    else:
                        # Display key metrics
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Risk Score", threat_analysis.get('risk_score', 'N/A'))
                        with col2:
                            st.metric("Is Scam", "Yes" if threat_analysis.get('is_scam', False) else "No")
                        with col3:
                            st.metric("Confidence", f"{threat_analysis.get('confidence', 0):.2f}")
                        
                        # Display summary and scam type
                        st.markdown("**Summary:**")
                        st.markdown(threat_analysis.get('summary', 'No summary available'))
                        
                        st.markdown("**Scam Type:**")
                        st.markdown(threat_analysis.get('scam_type', 'Unknown'))
                        
                        # Display red flags
                        if 'red_flags' in threat_analysis and threat_analysis['red_flags']:
                            st.markdown("**Red Flags:**")
                            for flag in threat_analysis['red_flags']:
                                st.markdown(f"- **{flag.get('flag', 'Unknown')}**: {flag.get('evidence', 'No evidence')}")
                        
                        # Display reasoning (collapsible to save space)
                        with st.expander("View Detailed Reasoning"):
                            st.markdown(threat_analysis.get('reasoning', 'No reasoning available'))
        else:
            st.info("No Threat Intelligence analysis available.")
    
    with tab6:
        # Display location verification for hotel-related websites
        hotel_results = [r for r in st.session_state.results if r['location_verification'].get('is_hotel_related', False)]
        
        if hotel_results:
            for result in hotel_results:
                item = result['result']
                location_verification = result['location_verification']
                
                with st.expander(f"Location Verification for {item['title']}"):
                    if location_verification.get('verified', False):
                        st.success("✅ Location Verified")
                        
                        # Display location details
                        st.markdown(f"**Place Name: {location_verification.get('place_name', 'Unknown')}")
                        st.markdown(f"**Address:** {location_verification.get('address', 'Unknown')}")
                        st.markdown(f"**Rating:** {location_verification.get('rating', 'N/A')}")
                        st.markdown(f"**Website:** {location_verification.get('website', 'Unknown')}")
                        
                        # Display photos if available
                        photos = location_verification.get('photos', [])
                        if photos:
                            st.markdown("**Photos:**")
                            for i, photo in enumerate(photos[:3]):  # Show up to 3 photos
                                photo_reference = photo.get('photo_reference', '')
                                if photo_reference:
                                    # Construct photo URL
                                    api_key = os.getenv("GOOGLE_MAPS_API_KEY")
                                    photo_url = f"https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference={photo_reference}&key={api_key}"
                                    st.image(photo_url, caption=f"Photo {i+1}")
                    else:
                        st.error("❌ Location Not Verified")
                        st.markdown(f"**Reason:** {location_verification.get('reason', 'Unknown')}")
        else:
            st.info("No hotel-related websites found for location verification.")
    
    with tab7:
        # Display activity logs
        if st.session_state.logs:
            # Filter logs to show only relevant ones
            relevant_logs = [log for log in st.session_state.logs if log['type'] in ['search', 'scam_detected', 'content_analysis', 'scamadviser_analysis', 'threat_intelligence_analysis']]
            
            if relevant_logs:
                for log in relevant_logs[-20:]:  # Show last 20 logs
                    with st.expander(f"{log['type'].replace('_', ' ').title()} - {log['timestamp']}"):
                        st.json(log['details'])
            else:
                st.info("No relevant activity logs found.")
        else:
            st.info("No activity logs found.")

# Footer
st.markdown("---")
st.markdown("Advanced Online Threat Detection System | Powered by Google Gemini AI and Fraud Keyword Analysis")