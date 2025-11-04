import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

class ContentFeatureExtractor:
    def __init__(self, url):
        self.url = url
        self.html = None
        self.soup = None
        self.domain = None
        
        try:
            # Parse URL for domain
            parsed_url = urlparse(url)
            self.domain = parsed_url.netloc
            if ':' in self.domain:  # Remove port if present
                self.domain = self.domain.split(':')[0]
                
            # Fetch and parse webpage
            response = requests.get(url, timeout=10)
            self.html = response.text
            self.soup = BeautifulSoup(self.html, 'html.parser')
        except:
            pass

    def extract_features(self):
        """Extract content-based features from webpage. Returns 18 features as expected by the model."""
        features = {}

        # Initialize with default values in case page can't be loaded
        if not self.soup:
            return [0] * 18  # Return zeros for all 18 features if page unreachable

        # HTML/Code Structure (2 features)
        features['LineOfCode'] = len(self.html.splitlines())
        features['LargestLineLength'] = max(len(line) for line in self.html.splitlines())

        # Page Elements (4 features)
        features['HasTitle'] = 1 if self.soup.title else 0
        features['HasDescription'] = 1 if self.soup.find('meta', attrs={'name': 'description'}) else 0
        features['HasCopyrightInfo'] = 1 if '©' in self.html or 'copyright' in self.html.lower() else 0
        features['HasSocialNet'] = 1 if any(net in self.html.lower() for net in ['facebook', 'twitter', 'instagram', 'linkedin']) else 0

        # Media & Resources (3 features)
        features['NoOfImage'] = len(self.soup.find_all('img'))
        features['NoOfCSS'] = len(self.soup.find_all('link', rel='stylesheet'))
        features['NoOfJS'] = len(self.soup.find_all('script'))

        # Forms Analysis (8 features)
        forms = self.soup.find_all('form')
        features['HasExternalFormSubmit'] = 0
        features['HasSubmitButton'] = 0
        features['HasHiddenFields'] = 0
        features['HasPasswordField'] = 0
        features['InsecureForms'] = 0
        features['RelativeFormAction'] = 0
        features['ExtFormAction'] = 0
        features['AbnormalFormAction'] = 0

        for form in forms:
            action = form.get('action', '')
            method = form.get('method', '').lower()
            
            # Check form submission
            if action and ('http' in action or '//' in action):
                features['HasExternalFormSubmit'] = 1
            
            # Check for submit buttons
            if form.find(['input', 'button'], attrs={'type': 'submit'}):
                features['HasSubmitButton'] = 1
            
            # Check for hidden fields
            if form.find('input', attrs={'type': 'hidden'}):
                features['HasHiddenFields'] = 1
            
            # Check for password fields
            if form.find('input', attrs={'type': 'password'}):
                features['HasPasswordField'] = 1
            
            # Check form security
            if method == 'get' or not action.startswith('https'):
                features['InsecureForms'] = 1
            
            # Check action URLs
            if action.startswith('/'):
                features['RelativeFormAction'] = 1
            elif action.startswith('http'):
                features['ExtFormAction'] = 1
            elif not action or action == '#' or action == 'javascript:void(0)':
                features['AbnormalFormAction'] = 1

        # Handle the NoOfSelfRef feature
        all_links = self.soup.find_all('a', href=True) if self.soup else []
        self_refs = 0
        if self.soup and self.domain:
            for link in all_links:
                href = link.get('href', '')
                if href and (self.domain in href or href.startswith('/')):
                    self_refs += 1
        features['NoOfSelfRef'] = self_refs

        # Return all 18 features expected by the model
        ordered_features = [
            'LineOfCode',
            'LargestLineLength',
            'HasTitle',
            'HasDescription',
            'HasCopyrightInfo',
            'HasSocialNet',
            'NoOfImage',
            'NoOfCSS',
            'NoOfJS',
            'HasExternalFormSubmit',
            'HasSubmitButton',
            'HasHiddenFields',
            'HasPasswordField',
            'InsecureForms',
            'RelativeFormAction',
            'ExtFormAction',
            'AbnormalFormAction',
            'NoOfSelfRef'  # Added this as the 18th feature
        ]
        return [features[f] for f in ordered_features]