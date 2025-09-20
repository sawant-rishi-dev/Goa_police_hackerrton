import os
import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser
import csv
import time  # Added for monitoring analyses
from datetime import datetime
from googleapiclient.discovery import build
from google import genai
from google.genai import types
import requests
from bs4 import BeautifulSoup
import spacy
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

# Load English language model for NLP
nlp = spacy.load("en_core_web_sm")

# Configure Gemini API model
GEMINI_MODEL = "gemini-1.5-flash"

# Predefined fraud keywords
FRAUD_KEYWORDS = {
    "financial_fraud": [
        "Urgent", "Immediate action required", "Confidential", "Secret deal",
        "Risk-free", "Guaranteed", "100% safe", "Act now", "Limited time offer",
        "Wire transfer", "Western Union", "Untraceable", "Off-the-books",
        "Pre-approved", "No questions asked", "Avoid taxes", "Tax loophole",
        "Congratulations, you've won", "Click here to claim", "Verify your account",
        "Confirm your identity", "Too good to be true", "Account suspended",
        "Locked account", "Shell company", "Falsified documents", "Dummy accounts",
        "Round-tripping", "Kickbacks", "Over-invoicing", "Under-invoicing",
        "Ghost employee", "Embezzlement", "Ponzi scheme", "Insider trading",
        "Money laundering", "Offshore account", "Stolen identity", "Phishing",
        "Spoofing", "Skimming", "Fake ID", "Forged documents",
        "Unauthorized transaction", "Chargeback fraud", "Dear customer",
        "Verify your password", "Click here to avoid suspension",
        "Update your billing information", "You've won a lottery", "Free prize",
        "Bank alert", "Backdate", "Side agreement", "Creative accounting",
        "Misstate", "Restate earnings", "Non-disclosed liabilities",
        "Unrecorded sales", "Under-the-table", "Inflated claim", "Staged accident",
        "False injury report", "Duplicate claims", "Lost receipts",
        "Unnecessary procedures"
    ],
    "prostitution_related": [
        "escort", "adult service", "erotic", "call girl", "sex worker",
        "prostitution", "sex work", "human trafficking", "sextrafficking",
        "stripper", "exotic dancer", "onlyfans", "porn", "sex industry",
        "sex trade", "red light district", "prostitute", "sexwork", "humantrafficking",
        "feminism", "sextrafficking", "prostitutes", "sexworkiswork", "nordicmodelnow",
        "prostitutionkillswomen", "sextrade", "sexindustry", "stopprostitution",
        "sexindustrykills", "queer", "redumbrella", "sexworkartwork", "truecrime",
        "lesbian", "gay", "sexworker", "sexworkerunite", "violencessexistes",
        "feminisme", "parapluierouge", "pornoprostitution", "porn",
        "noustoutes", "tdsnousexistons", "whore", "transgenre", "loi", "metooporn",
        "avril", "nordicmodel", "grindrr", "prostitutionisviolence", "enddemand",
        "savexx", "metooprostitution", "onarretetoutes", "abolishprostitution",
        "listentosurvivors", "neithersexnorwork", "murder", "sik", "sexy",
        "facesofprostitution", "keinemehr", "niunamenos", "stripper",
        "humantraffickingawareness", "femicide", "sexworkers", "poverty",
        "sexpositive", "exoticdancer", "harmreduction", "yesastripper",
        "sexworkersrights", "sexworkisrealwork", "sexworkersrightsarehumanrights",
        "sexworkersolidarity", "sexworkart", "sexworkshop", "sexworkisnotwork",
        "museumofprostitution", "childprostitution", "prostitutionwhore",
        "legalizeprostitution", "endprostitution", "prostitutionmuseum",
        "antiprostitution", "legalprostitution", "noprostitution",
        "forcedprostitution", "streetprostitution", "saynotoprostitution",
        "noprostitutionhere", "maleprostitution", "prostitutionring",
        "hashtagprostitution", "endchildprostitution", "fightchildprostitution",
        "notprostitution", "prostitution666", "freeartfromprostitution",
        "slangprostitution", "againstprostitution", "prostitutionmusic",
        "heatprostitution", "internationaldayofnoprostitution"
    ],
    "gambling_related": [
        "gambling", "betting", "casino", "sportsbetting", "sports bet",
        "online gambling", "gambling sites", "gambling games", "stake gambling",
        "sports gambling", "gambling websites", "illegal gambling",
        "twitch gambling", "casino gambling", "gambling machine",
        "online betting", "betting websites", "sports bets", "gambling",
        "online gambling", "gambling sites", "gambling games", "stake gambling",
        "rust gambling", "sports gambling", "gambling websites", "illegal gambling",
        "gamstop gambling", "roobet gambling", "responsible gambling",
        "twitch gambling", "casino gambling", "gambling machine", "bovada gambling",
        "bravado gambling", "gambling chips", "free gambling", "gambling insider",
        "reddit gambling", "gambling casino", "mobile gambling", "bravada gambling",
        "gambling table", "baccarat gambling", "gambling cards", "roulette gambling",
        "nba gambling", "football gambling", "roblox gambling", "skin gambling",
        "hollywood gambling", "gamdom", "bets", "sport bet", "online betting",
        "online casinos", "phone casino", "betmgm casino", "casino sites",
        "betting online", "twitch slots", "bodog canada", "csgo betting",
        "sporting bets", "csgo roulette", "explicit", "adult", "gambling",
        "casino", "earn money", "get rich", "quick cash", "betting", "adult content",
        "lottery", "fast money", "adult site", "sensual", "intimate", "mature content",
        "online casino", "adult dating", "x-rated", "win money", "jackpot",
        "sensual massage", "fast cash", "mature audience", "easy money", "betting tips",
        "adult entertainment", "make money fast", "adult chat", "XXX", "cash prize",
        "instant cash", "adult webcams", "high-stakes", "earn big", "explicit material",
        "get rich now", "adult offers", "gambling tips", "sensual content", "adult games",
        "easy winnings", "adult videos", "quick profit", "adult products", "fast earnings",
        "adult club", "adult model", "adult content provider", "high-risk bets",
        "adult party", "adult services", "adult classifieds", "mature dating",
        "adult fun", "adult personals", "adult chatroom", "sensual experience",
        "adult fantasy", "adult performers", "adult lifestyle", "adult website",
        "adult streaming", "adult platform", "adult membership", "adult community",
        "adult forum", "adult magazine", "adult network", "gambling strategy",
        "fast cash scheme", "get rich scheme", "casino tricks", "easy money scheme",
        "instant cash scheme", "betting scheme"
    ]
}

def update_content_csv(filename="content.csv"):
    keywords_categories = {
        "orange": ["hotel", "tourism", "goa political"],
        "green": ["vlogging", "food", "beauty of goa", "goa", "goan", "beaches"],
        "red": ["bars", "pubs", "drugs"]
    }
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Keyword", "Category"])  # Write header
        for category, keywords in keywords_categories.items():
            for keyword in keywords:
                writer.writerow([keyword, category])

# Fraud analysis functions
def extract_video_id(youtube_url):
    """Extract video ID from YouTube URL"""
    patterns = [
        r'(?:v=|\/)([0-9A-Za-z_-]{11}).*',
        r'(?:embed\/)([0-9A-Za-z_-]{11})',
        r'(?:youtu\.be\/)([0-9A-Za-z_-]{11})',
    ]
    for pattern in patterns:
        match = re.search(pattern, youtube_url, re.IGNORECASE)
        if match:
            return match.group(1)
    try:
        parsed_url = urlparse(youtube_url)
        if parsed_url.hostname in ['www.youtube.com', 'youtube.com']:
            query_params = parse_qs(parsed_url.query)
            return query_params.get('v', [None])[0]
        elif parsed_url.hostname == 'youtu.be':
            return parsed_url.path[1:]
    except Exception:
        pass
    return None

def get_youtube_video_info(video_id, api_key):
    """Get metadata and description from YouTube video"""
    try:
        youtube = build('youtube', 'v3', developerKey=api_key)
        # Fetch video details using the API
        request = youtube.videos().list(
            part='snippet',
            id=video_id
        )
        response = request.execute()
        video_details = response['items'][0]['snippet']
        # Extract video title
        title = video_details['title']
        # Extract video description
        description = video_details.get('description', 'No description provided')
        # Extract video tags
        tags = video_details.get('tags', [])
        # Extract video duration (this is a bit tricky as it's not directly in snippet)
        url = f"https://www.youtube.com/watch?v={video_id}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        duration = "Unknown duration"
        duration_meta = soup.find("meta", itemprop="duration")
        if duration_meta:
            duration = duration_meta["content"]
        return {
            "title": title,
            "description": description,
            "duration": duration,
            "url": url,
            "tags": tags
        }
    except Exception as e:
        print(f"Error fetching video info: {e}")
        return None

def summarize_with_gemini(text, api_key, summary_length="medium"):
    """Summarize text using Google Gemini API"""
    try:
        client = genai.Client(api_key=api_key)
        length_prompts = {
            "short": "Provide a brief 2-3 sentence summary based on the video's title, description, and metadata:",
            "medium": "Provide a comprehensive summary in 1-2 paragraphs analyzing the video's content based on its title, description, and available metadata:",
            "long": "Provide a detailed summary with bullet points covering what this video likely contains based on its title, description, and available metadata. Include potential topics and key points:"
        }
        prompt = f"""
        {length_prompts.get(summary_length, length_prompts["medium"])}
        Video Title: {text.get('title', 'No title')}
        Video Description: {text.get('description', 'No description provided')}
        Video Duration: {text.get('duration', 'Unknown')}
        Video Tags: {', '.join(text.get('tags', []))}
        Analyze this information to provide an intelligent summary of what this video likely contains.
        """
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.5,
                max_output_tokens=1000
            )
        )
        return response.text
    except Exception as e:
        print(f"Error with Gemini API: {e}")
        return None

def analyze_fraud_risk(summary):
    """Analyze the summary for fraudulent content using predefined keywords"""
    # Process the summary with NLP
    doc = nlp(summary.lower())
    # Initialize results
    results = {
        "fraud_detected": False,
        "categories": defaultdict(list),
        "risk_score": 0,
        "risk_level": "Low"
    }
    # Check for each keyword category
    for category, keywords in FRAUD_KEYWORDS.items():
        for keyword in keywords:
            # Look for keyword matches in the processed text
            pattern = re.compile(r'\b' + re.escape(keyword.lower()) + r'\b')
            matches = pattern.finditer(summary.lower())
            for match in matches:
                results["fraud_detected"] = True
                results["categories"][category].append({
                    "keyword": keyword,
                    "context": summary[max(0, match.start()-20):min(len(summary), match.end()+20)]
                })
                results["risk_score"] += 1
    # Determine risk level based on score
    if results["risk_score"] > 10:
        results["risk_level"] = "High"
    elif results["risk_score"] > 5:
        results["risk_level"] = "Medium"
    return results

def check_with_gemini_ai(summary, api_key):
    """Use Gemini AI to get a second opinion on fraud risk"""
    try:
        client = genai.Client(api_key=api_key)
        prompt = f"""
        Analyze the following YouTube video summary for potential fraudulent content.
        Consider these aspects when evaluating:
        1. Financial Fraud Indicators:
        - Promises of guaranteed returns or risk-free investments
        - Urgent or secret deals
        - Requests for wire transfers or unusual payment methods
        - Too-good-to-be-true offers
        2. Prostitution/Human Trafficking Indicators:
        - References to escort services or adult services
        - Language suggesting exploitation
        3. Gambling-Related Indicators:
        - Promotions of illegal gambling
        - References to sports betting or casino gambling
        Video Summary:
        {summary}
        Provide:
        1. A fraud risk assessment (Low/Medium/High)
        2. Specific concerns or indicators found
        3. Any suspicious phrases or patterns
        """
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=800
            )
        )
        return response.text
    except Exception as e:
        print(f"Error with Gemini AI analysis: {e}")
        return None

def summarize_and_analyze(youtube_url, gemini_api_key, summary_length="medium"):
    """Complete process: summarize and analyze for fraud"""
    print("🔍 Extracting video ID...")
    video_id = extract_video_id(youtube_url)
    if not video_id:
        return {"error": "Could not extract video ID from URL"}
    print(f"📹 Video ID: {video_id}")
    print("📝 Fetching video metadata...")
    video_info = get_youtube_video_info(video_id, gemini_api_key)  # Pass the API key here
    if not video_info:
        return {"error": "Could not fetch video information"}
    print(f"Found video: {video_info.get('title', 'Untitled')}")
    print(f"Duration: {video_info.get('duration', 'Unknown')}")
    print("🤖 Generating summary with Gemini AI...")
    summary = summarize_with_gemini(video_info, gemini_api_key, summary_length)
    if not summary:
        return {"error": "Could not generate summary"}
    print("🔎 Analyzing summary for fraud indicators using predefined keywords...")
    fraud_analysis = analyze_fraud_risk(summary)
    print("🤖 Getting AI second opinion...")
    ai_opinion = check_with_gemini_ai(summary, gemini_api_key)
    return {
        "video_id": video_id,
        "video_url": youtube_url,
        "video_title": video_info.get("title"),
        "video_description": video_info.get("description"),
        "video_duration": video_info.get("duration"),
        "summary": summary,
        "fraud_analysis": fraud_analysis,
        "ai_opinion": ai_opinion,
        "summary_length": summary_length,
        "tags": video_info.get("tags", [])
    }

# YouTube search functions
def scrape_latest_youtube_videos(keyword, max_results=10, api_key="AIzaSyCdDnn3iHwdi_ty-KYqpapp4VFW39E9Kv0"):
    """Fetch latest YouTube videos using the YouTube Data API, including views, likes, and upload time."""
    try:
        youtube = build('youtube', 'v3', developerKey=api_key)
        request = youtube.search().list(
            q=keyword,
            part='snippet',
            type='video',
            order='date',
            maxResults=max_results
        )
        response = request.execute()
        videos = []
        for item in response.get('items', []):
            video_id = item['id']['videoId']
            # Fetch additional details (views, likes, etc.)
            video_request = youtube.videos().list(
                part='statistics,snippet',
                id=video_id
            )
            video_response = video_request.execute()
            video_details = video_response['items'][0]
            videos.append({
                'title': item['snippet']['title'],
                'channel': item['snippet']['channelTitle'],
                'url': f"https://www.youtube.com/watch?v={video_id}",
                'publish_date': datetime.strptime(item['snippet']['publishedAt'], '%Y-%m-%dT%H:%M:%SZ'),
                'views': int(video_details['statistics'].get('viewCount', 0)),
                'likes': int(video_details['statistics'].get('likeCount', 0)),
                'upload_time': item['snippet']['publishedAt'],
                'description': video_details['snippet'].get('description', 'No description available')
            })
        return videos
    except Exception as e:
        print(f"API Error: {e}")
        return []

def fetch_video_comments(video_id, api_key):
    """Fetch comments for a video using the YouTube Data API."""
    try:
        youtube = build('youtube', 'v3', developerKey=api_key)
        request = youtube.commentThreads().list(
            part='snippet',
            videoId=video_id,
            maxResults=10  # Fetch up to 10 comments
        )
        response = request.execute()
        comments = []
        for item in response.get('items', []):
            comment = item['snippet']['topLevelComment']['snippet']
            comments.append({
                'author': comment['authorDisplayName'],
                'text': comment['textDisplay'],
                'published_at': comment['publishedAt']
            })
        return comments
    except Exception as e:
        print(f"Error fetching comments: {e}")
        return []

def log_video_details_to_file(videos, api_key, filename="youtube_video_details.txt"):
    """Log video details and comments to a text file."""
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            for video in videos:
                file.write(f"Title: {video['title']}\n")
                file.write(f"Channel: {video['channel']}\n")
                file.write(f"URL: {video['url']}\n")
                file.write(f"Views: {video['views']}\n")
                file.write(f"Likes: {video['likes']}\n")
                file.write(f"Upload Time: {video['upload_time']}\n")
                file.write(f"Description: {video['description']}\n")
                # Fetch and log comments
                video_id = video['url'].split('v=')[1]
                comments = fetch_video_comments(video_id, api_key)
                file.write(f"Comments ({len(comments)}):\n")
                for comment in comments:
                    file.write(f"  - {comment['author']}: {comment['text']}\n")
                file.write("\n" + "="*50 + "\n\n")
        print(f"Video details logged to {filename}")
    except Exception as e:
        print(f"Error logging video details: {e}")

def export_to_csv(videos, api_key, filename="youtube_video_details.csv"):
    """Export video details and comments to a CSV file."""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            # Write header
            writer.writerow([
                'Title', 'Channel', 'URL', 'Views', 'Likes', 'Upload Time', 'Description', 'Comments'
            ])
            # Write video details
            for video in videos:
                video_id = video['url'].split('v=')[1]
                comments = fetch_video_comments(video_id, api_key)
                comments_text = "\n".join([f"{comment['author']}: {comment['text']}" for comment in comments])
                writer.writerow([
                    video['title'],
                    video['channel'],
                    video['url'],
                    video['views'],
                    video['likes'],
                    video['upload_time'],
                    video['description'],
                    comments_text
                ])
        print(f"Video details exported to {filename}")
    except Exception as e:
        print(f"Error exporting to CSV: {e}")

# Website search functions
def search_website(url, keywords):
    """Search a website for specific keywords"""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text().lower()
        found_keywords = []
        for keyword in keywords:
            if keyword.lower() in text:
                found_keywords.append(keyword)
        return found_keywords
    except Exception as e:
        print(f"Error searching website: {e}")
        return []

def analyze_website(url):
    """Analyze a website for fraudulent content"""
    # Combine all keywords into a single list
    all_keywords = []
    for category, keywords in FRAUD_KEYWORDS.items():
        all_keywords.extend(keywords)
    found_keywords = search_website(url, all_keywords)
    return found_keywords

# GUI class integrating both functionalities with automatic fraud analysis
class YouTubeSearcherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("YouTube Latest Videos Scraper with Auto Fraud Analysis")
        self.root.geometry("1100x900")  # Increased height for analysis section
        self.root.configure(bg='#f0f0f0')
        # Title
        title_label = tk.Label(
            root, text="YouTube Latest Videos Scraper with Auto Fraud Analysis",
            font=('Arial', 16, 'bold'), bg='#f0f0f0', fg='#333'
        )
        title_label.pack(pady=10)
        # Search frame
        search_frame = tk.Frame(root, bg='#f0f0f0')
        search_frame.pack(pady=10, padx=20, fill='x')
        tk.Label(
            search_frame, text="Keyword:", font=('Arial', 12),
            bg='#f0f0f0'
        ).pack(side='left')
        self.keyword_entry = tk.Entry(
            search_frame, font=('Arial', 12), width=30
        )
        self.keyword_entry.pack(side='left', padx=10)
        self.search_btn = tk.Button(
            search_frame, text="Search & Analyze",
            command=self.search_videos,
            bg='#4CAF50', fg='white', font=('Arial', 12),
            relief='flat', padx=20
        )
        self.search_btn.pack(side='left', padx=10)
        
        # Add info label about automatic analysis
        info_label = tk.Label(
            root, text="ℹ️ Fraud analysis will run automatically after search completes",
            font=('Arial', 10, 'italic'), bg='#f0f0f0', fg='#666'
        )
        info_label.pack(pady=5)
        
        # Results frame
        results_frame = tk.Frame(root, bg='#f0f0f0')
        results_frame.pack(pady=10, padx=20, fill='both', expand=True)
        tk.Label(
            results_frame, text="Search Results:", font=('Arial', 12, 'bold'),
            bg='#f0f0f0'
        ).pack(anchor='w')
        
        # Create Treeview with additional columns including fraud status
        columns = ('No', 'Title', 'Channel', 'Views', 'Likes', 'Upload Time', 'Fraud Status', 'Action')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=12)
        
        # Define headings
        self.tree.heading('No', text='#')
        self.tree.heading('Title', text='Video Title')
        self.tree.heading('Channel', text='Channel')
        self.tree.heading('Views', text='Views')
        self.tree.heading('Likes', text='Likes')
        self.tree.heading('Upload Time', text='Upload Time')
        self.tree.heading('Fraud Status', text='Fraud Status')
        self.tree.heading('Action', text='Action')
        
        # Define column widths
        self.tree.column('No', width=50)
        self.tree.column('Title', width=250)
        self.tree.column('Channel', width=120)
        self.tree.column('Views', width=70)
        self.tree.column('Likes', width=70)
        self.tree.column('Upload Time', width=120)
        self.tree.column('Fraud Status', width=100)
        self.tree.column('Action', width=80)
        
        self.tree.pack(fill='both', expand=True)
        # Bind double-click event
        self.tree.bind('<Double-1>', self.open_video)
        
        # Status label
        self.status_label = tk.Label(
            root, text="Ready", font=('Arial', 10),
            bg='#f0f0f0', fg='#666'
        )
        self.status_label.pack(pady=5)
        
        # Add a frame for fraud analysis results
        self.analysis_frame = tk.Frame(root, bg='#f0f0f0')
        self.analysis_frame.pack(pady=10, padx=20, fill='both', expand=True)
        tk.Label(
            self.analysis_frame, text="Fraud Analysis Results:", font=('Arial', 12, 'bold'),
            bg='#f0f0f0'
        ).pack(anchor='w')
        
        # Add scrollbar to analysis text
        text_frame = tk.Frame(self.analysis_frame)
        text_frame.pack(fill='both', expand=True)
        
        self.analysis_text = tk.Text(
            text_frame, height=12, width=100,
            font=('Arial', 10), wrap='word'
        )
        scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=self.analysis_text.yview)
        self.analysis_text.configure(yscrollcommand=scrollbar.set)
        
        self.analysis_text.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Website analysis section
        website_frame = tk.Frame(root, bg='#f0f0f0')
        website_frame.pack(pady=10, padx=20, fill='x')
        tk.Label(
            website_frame, text="Website URL:", font=('Arial', 12),
            bg='#f0f0f0'
        ).pack(side='left')
        self.website_entry = tk.Entry(
            website_frame, font=('Arial', 12), width=30
        )
        self.website_entry.pack(side='left', padx=10)
        self.website_btn = tk.Button(
            website_frame, text="Analyze Website",
            command=self.analyze_website,
            bg='#FF9800', fg='white', font=('Arial', 12),
            relief='flat', padx=20
        )
        self.website_btn.pack(side='left', padx=10)
        
        # Website analysis results
        self.website_results_frame = tk.Frame(root, bg='#f0f0f0')
        self.website_results_frame.pack(pady=10, padx=20, fill='both', expand=True)
        tk.Label(
            self.website_results_frame, text="Website Analysis Results:", font=('Arial', 12, 'bold'),
            bg='#f0f0f0'
        ).pack(anchor='w')
        
        self.website_results_text = tk.Text(
            self.website_results_frame, height=10, width=100,
            font=('Arial', 10), wrap='word'
        )
        self.website_results_text.pack(fill='both', expand=True)
        
        # Store videos data
        self.videos_data = []
        # Store analysis results
        self.all_results = []
        # Gemini API key (could be input by user or stored securely)
        self.gemini_api_key = "AIzaSyDd1FVB7YCLc6tyORRN_T67fktUMQPN0_A"  # Placeholder
        self.youtube_api_key = "AIzaSyCdDnn3iHwdi_ty-KYqpapp4VFW39E9Kv0"
        
        # Progress tracking
        self.analysis_progress = 0
        self.total_videos = 0

    def search_videos(self):
        keyword = self.keyword_entry.get().strip()
        if not keyword:
            messagebox.showerror("Error", "Please enter a keyword")
            return
        self.search_btn.config(state='disabled', text='Searching...')
        self.status_label.config(text="Searching YouTube...")
        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.analysis_text.delete(1.0, tk.END)
        self.all_results = []
        # Run search in separate thread
        thread = threading.Thread(target=self.perform_search, args=(keyword,))
        thread.daemon = True
        thread.start()

    def perform_search(self, keyword):
        try:
            videos = scrape_latest_youtube_videos(keyword, max_results=10, api_key=self.youtube_api_key)
            if len(videos) < 10:
                # If we don't have enough videos, fetch more
                additional_videos = scrape_latest_youtube_videos(keyword, max_results=10 - len(videos), api_key=self.youtube_api_key)
                videos.extend(additional_videos)
            self.videos_data = videos[:10]  # Ensure we have exactly 10 videos
            log_video_details_to_file(videos, api_key=self.youtube_api_key)
            export_to_csv(videos, api_key=self.youtube_api_key)
            self.root.after(0, self.update_results, videos)
            # Automatically start fraud analysis after search completes
            if videos:
                self.root.after(100, self.start_automatic_analysis)
        except Exception as e:
            self.root.after(0, self.show_error, str(e))

    def update_results(self, videos):
        if videos:
            for i, video in enumerate(videos, 1):
                self.tree.insert('', 'end', values=(
                    i,
                    video['title'][:50] + "..." if len(video['title']) > 50 else video['title'],
                    video['channel'],
                    f"{video['views']:,}",
                    f"{video['likes']:,}",
                    video['upload_time'][:10] + " " + video['upload_time'][11:19],
                    'Analyzing...',  # Initial fraud status
                    'Open Link'
                ))
            self.status_label.config(text=f"Found {len(videos)} videos - Starting automatic fraud analysis...")
        else:
            self.status_label.config(text="No videos found")
            self.search_btn.config(state='normal', text='Search & Analyze')

    def start_automatic_analysis(self):
        if not self.videos_data:
            return
        
        self.total_videos = len(self.videos_data)
        self.analysis_progress = 0
        self.all_results = []
        
        self.analysis_text.delete(1.0, tk.END)
        self.analysis_text.insert(tk.END, f"🔍 Starting automatic fraud analysis of {self.total_videos} videos...\n\n")
        
        # Start analysis for each video in separate threads
        for i, video in enumerate(self.videos_data):
            thread = threading.Thread(target=self.perform_analysis, args=(video['url'], i))
            thread.daemon = True
            thread.start()
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_analyses, args=(self.total_videos,))
        monitor_thread.daemon = True
        monitor_thread.start()

    def monitor_analyses(self, total_videos):
        while len(self.all_results) < total_videos:
            time.sleep(0.1)
            # Update progress in status
            current_progress = len(self.all_results)
            self.root.after(0, self.update_progress, current_progress, total_videos)
        
        # All analyses complete
        self.root.after(0, self.display_all_analyses)

    def update_progress(self, current, total):
        self.status_label.config(text=f"Analyzing videos... {current}/{total} complete")

    def perform_analysis(self, video_url, video_index):
        try:
            result = summarize_and_analyze(video_url, self.gemini_api_key)
            if "error" in result:
                # If there's an error, create a result with a placeholder summary
                result = {
                    "video_id": extract_video_id(video_url),
                    "video_url": video_url,
                    "video_title": "Unknown Title",
                    "video_description": "No description available",
                    "video_duration": "Unknown duration",
                    "summary": "++",
                    "fraud_analysis": {"fraud_detected": False, "categories": {}, "risk_score": 0, "risk_level": "Low"},
                    "ai_opinion": "No analysis available",
                    "summary_length": "medium",
                    "tags": []
                }
            result['video_index'] = video_index
            self.all_results.append(result)
            
            # Update the tree view with fraud status
            fraud_status = "❌ Error"
            if "error" not in result:
                if result['fraud_analysis']['fraud_detected']:
                    risk_level = result['fraud_analysis']['risk_level']
                    if risk_level == "High":
                        fraud_status = "🔴 High Risk"
                    elif risk_level == "Medium":
                        fraud_status = "🟡 Medium Risk"
                    else:
                        fraud_status = "🟠 Low Risk"
                else:
                    fraud_status = "✅ Clean"
            
            # Update the specific row in the tree
            self.root.after(0, self.update_tree_fraud_status, video_index, fraud_status)
            
        except Exception as e:
            # If there's an exception, create a result with a placeholder summary
            result = {
                "video_id": extract_video_id(video_url),
                "video_url": video_url,
                "video_title": "Unknown Title",
                "video_description": "No description available",
                "video_duration": "Unknown duration",
                "summary": "++",
                "fraud_analysis": {"fraud_detected": False, "categories": {}, "risk_score": 0, "risk_level": "Low"},
                "ai_opinion": "No analysis available",
                "summary_length": "medium",
                "tags": [],
                "video_index": video_index
            }
            self.all_results.append(result)
            self.root.after(0, self.update_tree_fraud_status, video_index, "❌ Error")

    def update_tree_fraud_status(self, video_index, fraud_status):
        # Find and update the specific tree item
        for item in self.tree.get_children():
            values = list(self.tree.item(item)['values'])
            if int(values[0]) == video_index + 1:  # Match by video number
                values[6] = fraud_status  # Update fraud status column
                self.tree.item(item, values=values)
                break

    def display_all_analyses(self):
        self.analysis_text.delete(1.0, tk.END)
        
        # Sort results by video index to maintain order
        sorted_results = sorted(self.all_results, key=lambda x: x.get('video_index', 0))
        
        high_risk_count = 0
        medium_risk_count = 0
        clean_count = 0
        error_count = 0
        
        for i, result in enumerate(sorted_results, 1):
            self.analysis_text.insert(tk.END, f"\n{'='*60}\n")
            self.analysis_text.insert(tk.END, f"🎥 VIDEO {i} ANALYSIS\n")
            self.analysis_text.insert(tk.END, f"{'='*60}\n")
            
            if "error" in result:
                self.analysis_text.insert(tk.END, f"❌ Error: {result['error']}\n")
                error_count += 1
            else:
                self.analysis_text.insert(tk.END, f"📹 Title: {result['video_title']}\n")
                self.analysis_text.insert(tk.END, f"🔗 URL: {result['video_url']}\n\n")
                
                summary = result.get('summary', '++')
                self.analysis_text.insert(tk.END, f"📝 SUMMARY:\n{summary}\n\n")
                
                if not result['fraud_analysis']['fraud_detected']:
                    self.analysis_text.insert(tk.END, "✅ FRAUD ANALYSIS: No fraud indicators detected - Video appears clean\n")
                    clean_count += 1
                else:
                    risk_level = result['fraud_analysis']['risk_level']
                    risk_emoji = "🔴" if risk_level == "High" else "🟡" if risk_level == "Medium" else "🟠"
                    
                    self.analysis_text.insert(tk.END, f"{risk_emoji} FRAUD ANALYSIS: Potential fraud indicators detected!\n")
                    self.analysis_text.insert(tk.END, f"Risk Level: {risk_level}\n")
                    self.analysis_text.insert(tk.END, f"Risk Score: {result['fraud_analysis']['risk_score']}\n\n")
                    
                    if risk_level == "High":
                        high_risk_count += 1
                    elif risk_level == "Medium":
                        medium_risk_count += 1
                    
                    for category, items in result['fraud_analysis']['categories'].items():
                        self.analysis_text.insert(tk.END, f"📌 {category.replace('_', ' ').title()}:\n")
                        for item in items[:3]:  # Show first 3 examples
                            self.analysis_text.insert(tk.END, f"   • Keyword: '{item['keyword']}'\n")
                            self.analysis_text.insert(tk.END, f"   • Context: ...{item['context']}...\n")
                        self.analysis_text.insert(tk.END, "\n")
                
                ai_opinion = result.get('ai_opinion', 'No analysis available')
                self.analysis_text.insert(tk.END, f"🤖 AI OPINION:\n{ai_opinion}\n")
        
        # Add summary at the end
        self.analysis_text.insert(tk.END, f"\n{'='*60}\n")
        self.analysis_text.insert(tk.END, "📊 ANALYSIS SUMMARY\n")
        self.analysis_text.insert(tk.END, f"{'='*60}\n")
        self.analysis_text.insert(tk.END, f"🔴 High Risk Videos: {high_risk_count}\n")
        self.analysis_text.insert(tk.END, f"🟡 Medium Risk Videos: {medium_risk_count}\n")
        self.analysis_text.insert(tk.END, f"✅ Clean Videos: {clean_count}\n")
        self.analysis_text.insert(tk.END, f"❌ Analysis Errors: {error_count}\n")
        self.analysis_text.insert(tk.END, f"📈 Total Videos Analyzed: {len(sorted_results)}\n")
        
        # Scroll to top
        self.analysis_text.see(1.0)
        
        # Update status and re-enable search button
        self.search_btn.config(state='normal', text='Search & Analyze')
        self.status_label.config(text=f"Analysis complete: {high_risk_count} high risk, {medium_risk_count} medium risk, {clean_count} clean videos")

    def show_error(self, error_msg):
        self.status_label.config(text=f"Error: {error_msg}")
        self.search_btn.config(state='normal', text='Search & Analyze')
        messagebox.showerror("Search Error", f"Failed to search: {error_msg}")

    def open_video(self, _event):
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            video_index = int(item['values'][0]) - 1
            if 0 <= video_index < len(self.videos_data):
                video_url = self.videos_data[video_index]['url']
                webbrowser.open(video_url)
                self.status_label.config(text=f"Opened: {self.videos_data[video_index]['title'][:50]}...")

    def analyze_website(self):
        url = self.website_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a website URL")
            return
        self.website_btn.config(state='disabled', text='Analyzing...')
        self.status_label.config(text="Analyzing website...")
        self.website_results_text.delete(1.0, tk.END)
        # Run analysis in separate thread
        thread = threading.Thread(target=self.perform_website_analysis, args=(url,))
        thread.daemon = True
        thread.start()

    def perform_website_analysis(self, url):
        try:
            found_keywords = analyze_website(url)
            self.root.after(0, self.display_website_analysis, found_keywords)
        except Exception as e:
            self.root.after(0, self.show_website_error, str(e))

    def display_website_analysis(self, found_keywords):
        self.website_results_text.delete(1.0, tk.END)
        if found_keywords:
            self.website_results_text.insert(tk.END, f"Found {len(found_keywords)} potential fraud keywords:\n\n")
            for keyword in found_keywords:
                self.website_results_text.insert(tk.END, f"- {keyword}\n")
        else:
            self.website_results_text.insert(tk.END, "No fraud keywords found on the website.")
        self.website_btn.config(state='normal', text='Analyze Website')
        self.status_label.config(text="Website analysis complete")

    def show_website_error(self, error_msg):
        self.website_results_text.delete(1.0, tk.END)
        self.website_results_text.insert(tk.END, f"Error during analysis: {error_msg}")
        self.website_btn.config(state='normal', text='Analyze Website')
        self.status_label.config(text=f"Analysis error: {error_msg}")

if __name__ == "__main__":
    update_content_csv()  # Update the CSV file when the script starts
    root = tk.Tk()
    app = YouTubeSearcherGUI(root)
    root.mainloop()
