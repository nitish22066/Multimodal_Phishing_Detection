import re
from urllib.parse import urlparse
import tld
import os.path
import socket
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import dns.resolver
import time
import pandas as pd
import whois
import numpy as np

class FeatureExtraction2:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            self.response = None
            self.soup = None

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            self.urlparse = None
            self.domain = None

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

    def extract_features(self):
        features = {}
        
        # URL-based features
        features['length_url'] = len(self.url)
        features['length_hostname'] = len(self.domain) if self.domain else 0
        features['ip'] = self._is_ip()
        features['nb_dots'] = self.url.count('.')
        features['nb_hyphens'] = self.url.count('-')
        features['nb_at'] = self.url.count('@')
        features['nb_qm'] = self.url.count('?')
        features['nb_and'] = self.url.count('&')
        features['nb_or'] = self.url.count('|')
        features['nb_eq'] = self.url.count('=')
        features['nb_underscore'] = self.url.count('_')
        features['nb_tilde'] = self.url.count('~')
        features['nb_percent'] = self.url.count('%')
        features['nb_slash'] = self.url.count('/')
        features['nb_star'] = self.url.count('*')
        features['nb_colon'] = self.url.count(':')
        features['nb_comma'] = self.url.count(',')
        features['nb_semicolumn'] = self.url.count(';')
        features['nb_dollar'] = self.url.count('$')
        features['nb_space'] = self.url.count(' ')
        features['nb_www'] = 1 if 'www' in self.url else 0
        features['nb_com'] = 1 if '.com' in self.url else 0
        features['nb_dslash'] = self.url.count('//')

        # Advanced URL features
        # URL path analysis
        features['http_in_path'] = 1 if self.urlparse and 'http' in self.urlparse.path.lower() else 0
        features['https_token'] = 1 if 'https' in self.url else 0
        features['ratio_digits_url'] = sum(c.isdigit() for c in self.url) / len(self.url)
        features['ratio_digits_host'] = sum(c.isdigit() for c in self.domain) / len(self.domain) if self.domain else 0
        features['punycode'] = 1 if self.domain and 'xn--' in self.domain.lower() else 0
        features['port'] = 1 if self.urlparse and self.urlparse.port else 0
        
        # Domain features
        # TLD and domain analysis
        try:
            domain_tld = tld.get_tld(self.url, fail_silently=True)
            features['tld_in_path'] = 1 if self.urlparse and domain_tld in self.urlparse.path else 0
        except:
            features['tld_in_path'] = 0
            
        features['tld_in_subdomain'] = 0  # Requires more complex parsing
        features['abnormal_subdomain'] = 0  # Requires known patterns
        features['nb_subdomains'] = len(self.domain.split('.')) - 1 if self.domain else 0
        features['prefix_suffix'] = 1 if self.domain and '-' in self.domain else 0
        features['random_domain'] = 0  # Requires entropy calculation
        features['shortening_service'] = self._is_shortening_service()
        
        # Path features
        features['path_extension'] = self._has_suspicious_extension()
        features['nb_redirection'] = len(self.response.history) if self.response else 0
        features['nb_external_redirection'] = 0  # Requires following redirects
        
        # Words analysis
        words_raw = re.findall(r'\w+', self.url.lower())
        features['length_words_raw'] = len(words_raw)
        features['char_repeat'] = self._get_repeating_characters()
        features['shortest_words_raw'] = min(len(w) for w in words_raw) if words_raw else 0
        features['shortest_word_host'] = min(len(w) for w in self.domain.split('.')) if self.domain else 0
        features['shortest_word_path'] = min(len(w) for w in self.urlparse.path.split('/')) if self.urlparse and self.urlparse.path else 0
        features['longest_words_raw'] = max(len(w) for w in words_raw) if words_raw else 0
        features['longest_word_host'] = max(len(w) for w in self.domain.split('.')) if self.domain else 0
        features['longest_word_path'] = max(len(w) for w in self.urlparse.path.split('/')) if self.urlparse and self.urlparse.path else 0
        features['avg_words_raw'] = sum(len(w) for w in words_raw) / len(words_raw) if words_raw else 0
        features['avg_word_host'] = sum(len(w) for w in self.domain.split('.')) / len(self.domain.split('.')) if self.domain else 0
        features['avg_word_path'] = sum(len(w) for w in self.urlparse.path.split('/')) / len(self.urlparse.path.split('/')) if self.urlparse and self.urlparse.path else 0

        # Brand features
        features['phish_hints'] = self._has_phishing_hints()
        features['domain_in_brand'] = 0  # Requires brand database
        features['brand_in_subdomain'] = 0  # Requires brand database
        features['brand_in_path'] = 0  # Requires brand database
        features['suspecious_tld'] = self._has_suspicious_tld()
        features['statistical_report'] = 1  # Placeholder

        # HTML and JavaScript features
        if self.soup:
            features['nb_hyperlinks'] = len(self.soup.find_all('a', href=True))
            int_links, ext_links, null_links = self._analyze_hyperlinks()
            total_links = int_links + ext_links + null_links
            features['ratio_intHyperlinks'] = int_links / total_links if total_links > 0 else 0
            features['ratio_extHyperlinks'] = ext_links / total_links if total_links > 0 else 0
            features['ratio_nullHyperlinks'] = null_links / total_links if total_links > 0 else 0
            features['nb_extCSS'] = len(self.soup.find_all('link', rel='stylesheet', href=True))
            features['ratio_intRedirection'] = self._get_redirection_ratio()[0]
            features['ratio_extRedirection'] = self._get_redirection_ratio()[1]
            features['ratio_intErrors'] = 0  # Requires response analysis
            features['ratio_extErrors'] = 0  # Requires response analysis
            features['login_form'] = 1 if self.soup.find('input', {'type': 'password'}) else 0
            features['external_favicon'] = self._has_external_favicon()
            features['links_in_tags'] = len(self.soup.find_all(['link', 'script', 'img']))
            features['submit_email'] = 1 if self.soup.find('input', {'type': 'email'}) else 0
            features['ratio_intMedia'] = self._get_media_ratio()[0]
            features['ratio_extMedia'] = self._get_media_ratio()[1]
            features['sfh'] = self._has_suspicious_form_handler()
            features['iframe'] = 1 if self.soup.find('iframe') else 0
            features['popup_window'] = 1 if 'window.open' in str(self.soup) else 0
            features['safe_anchor'] = 0  # Requires complex analysis
            features['onmouseover'] = 1 if 'onmouseover' in str(self.soup) else 0
            features['right_clic'] = 1 if 'event.button==2' in str(self.soup) else 0
            features['empty_title'] = 1 if not self.soup.title or not self.soup.title.string else 0
            features['domain_in_title'] = 1 if self.domain and self.soup.title and self.domain in str(self.soup.title) else 0
            features['domain_with_copyright'] = 1 if self.domain and '©' in str(self.soup) and self.domain in str(self.soup) else 0
        else:
            # Set default values if soup is None
            html_features = ['nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 
                           'ratio_nullHyperlinks', 'nb_extCSS', 'ratio_intRedirection',
                           'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors',
                           'login_form', 'external_favicon', 'links_in_tags', 'submit_email',
                           'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe', 'popup_window',
                           'safe_anchor', 'onmouseover', 'right_clic', 'empty_title',
                           'domain_in_title', 'domain_with_copyright']
            for feature in html_features:
                features[feature] = 0

        # WHOIS features
        features['whois_registered_domain'] = 1 if self.whois_response and self.whois_response.domain_name else 0
        features['domain_registration_length'] = self._get_domain_registration_length()
        features['domain_age'] = self._get_domain_age()
        features['web_traffic'] = 0  # Requires Alexa rank
        features['dns_record'] = self._has_dns_record()
        features['google_index'] = 0  # Requires Google API
        features['page_rank'] = 0  # Requires PageRank API

        # Convert dictionary to list maintaining order
        ordered_features = [
            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
            'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
            'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma',
            'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com',
            'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url',
            'ratio_digits_host', 'punycode', 'port', 'tld_in_path',
            'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains',
            'prefix_suffix', 'random_domain', 'shortening_service',
            'path_extension', 'nb_redirection', 'nb_external_redirection',
            'length_words_raw', 'char_repeat', 'shortest_words_raw',
            'shortest_word_host', 'shortest_word_path', 'longest_words_raw',
            'longest_word_host', 'longest_word_path', 'avg_words_raw',
            'avg_word_host', 'avg_word_path', 'phish_hints', 'domain_in_brand',
            'brand_in_subdomain', 'brand_in_path', 'suspecious_tld',
            'statistical_report', 'nb_hyperlinks', 'ratio_intHyperlinks',
            'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS',
            'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors',
            'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags',
            'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe',
            'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
            'empty_title', 'domain_in_title', 'domain_with_copyright',
            'whois_registered_domain', 'domain_registration_length', 'domain_age',
            'web_traffic', 'dns_record', 'google_index', 'page_rank'
        ]
        return [features[f] for f in ordered_features]

    def _is_ip(self):
        """Check if domain is an IP address."""
        try:
            socket.inet_aton(self.domain)
            return 1
        except:
            return 0

    def _is_shortening_service(self):
        """Check if URL is a known shortening service."""
        shortening_services = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd']
        if not self.domain:
            return 0
        return 1 if any(service in self.domain.lower() for service in shortening_services) else 0

    def _has_suspicious_extension(self):
        """Check for suspicious file extensions."""
        suspicious_extensions = ['.exe', '.zip', '.rar', '.pdf', '.doc', '.docx', '.xls', '.xlsx']
        if not self.urlparse:
            return 0
        return 1 if any(ext in self.urlparse.path.lower() for ext in suspicious_extensions) else 0

    def _get_repeating_characters(self):
        """Calculate ratio of repeating characters."""
        if not self.domain:
            return 0
        count = 0
        for i in range(len(self.domain)-1):
            if self.domain[i] == self.domain[i+1]:
                count += 1
        return count

    def _has_phishing_hints(self):
        """Check for common phishing words."""
        phishing_words = ['login', 'signin', 'verify', 'bank', 'account', 'update', 'security']
        return 1 if any(word in self.url.lower() for word in phishing_words) else 0

    def _has_suspicious_tld(self):
        """Check for suspicious TLDs."""
        suspicious_tlds = ['.tk', '.xyz', '.top', '.work', '.date', '.bid', '.download']
        if not self.domain:
            return 0
        return 1 if any(tld in self.domain.lower() for tld in suspicious_tlds) else 0

    def _analyze_hyperlinks(self):
        """Analyze hyperlinks in the page."""
        if not self.soup or not self.domain:
            return 0, 0, 0
        
        internal = 0
        external = 0
        null = 0
        
        for a in self.soup.find_all('a', href=True):
            href = a['href']
            if not href or href == "#":
                null += 1
            elif self.domain in href:
                internal += 1
            else:
                external += 1
        
        return internal, external, null

    def _has_external_favicon(self):
        """Check if favicon is loaded from external domain."""
        if not self.soup or not self.domain:
            return 0
        
        for link in self.soup.find_all('link', rel='icon'):
            if 'href' in link.attrs and self.domain not in link['href']:
                return 1
        return 0

    def _get_media_ratio(self):
        """Calculate ratio of internal/external media."""
        if not self.soup or not self.domain:
            return 0, 0
        
        internal = 0
        external = 0
        media_tags = self.soup.find_all(['img', 'video', 'audio'])
        
        for tag in media_tags:
            src = tag.get('src', '')
            if src:
                if self.domain in src:
                    internal += 1
                else:
                    external += 1
        
        total = internal + external
        return (internal/total if total > 0 else 0, external/total if total > 0 else 0)

    def _get_redirection_ratio(self):
        """Calculate ratio of internal/external redirections."""
        if not self.soup or not self.domain:
            return 0, 0
        
        internal = 0
        external = 0
        redirects = self.soup.find_all('meta', attrs={'http-equiv': 'refresh'})
        
        for redirect in redirects:
            content = redirect.get('content', '')
            if self.domain in content:
                internal += 1
            else:
                external += 1
        
        total = internal + external
        return (internal/total if total > 0 else 0, external/total if total > 0 else 0)

    def _has_suspicious_form_handler(self):
        """Check for suspicious form handlers."""
        if not self.soup:
            return 0
        
        for form in self.soup.find_all('form'):
            action = form.get('action', '')
            if not action or action == "about:blank":
                return 1
        return 0

    def _get_domain_registration_length(self):
        """Calculate domain registration length in days."""
        if not self.whois_response:
            return 0
        
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if expiration_date and creation_date:
                return (expiration_date - creation_date).days
        except:
            pass
        return 0

    def _get_domain_age(self):
        """Calculate domain age in days."""
        if not self.whois_response:
            return 0
        
        try:
            creation_date = self.whois_response.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                return (datetime.now() - creation_date).days
        except:
            pass
        return 0

    def _has_dns_record(self):
        """Check if domain has DNS records."""
        try:
            dns.resolver.resolve(self.domain, 'A')
            return 1
        except:
            return 0