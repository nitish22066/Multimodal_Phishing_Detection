import streamlit as st
import pandas as pd
import numpy as np
import pickle
import os
import sys
import importlib
import warnings
import whois
import dns.resolver
import requests
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import re

warnings.filterwarnings('ignore')

# Validate runtime environment and load critical resources early so errors show up
# during launch rather than at a later user action.

# Model paths for different detection approaches
NETWORK_MODEL_PATH = os.path.join("Models", "model_network_analysis.pkl")  # Network analysis
STRUCTURE_MODEL_PATH = os.path.join("Models", "phishing_structure_analysis.pkl")  # Structural analysis
CONTENT_MODEL_PATH = os.path.join("Models", "phishing_page_content_analysis.pkl")  # Content analysis

# Global model objects (loaded at startup)
NETWORK_MODEL = None  # For network analysis
STRUCTURE_MODEL = None  # For structural analysis
CONTENT_MODEL = None  # For content analysis


def _find_model_file(root_dir: str):
    """Search workspace for plausible model .pkl files and return a list of candidates."""
    candidates = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            if fn.lower().endswith('.pkl') and ('model' in fn.lower() or 'phish' in fn.lower()):
                candidates.append(os.path.join(dirpath, fn))
    return candidates


def validate_and_load_model():
    """Ensure model files exist, load them and verify they provide predict_proba.

    Raises clear FileNotFoundError or RuntimeError with suggestions when something is
    missing or incompatible.
    """
    global NETWORK_MODEL, STRUCTURE_MODEL, CONTENT_MODEL
    project_root = os.path.dirname(os.path.realpath(__file__))

    # Load network analysis model
    network_path = os.path.join(project_root, NETWORK_MODEL_PATH)
    if not os.path.isfile(network_path):
        raise FileNotFoundError(f"Network analysis model not found at '{NETWORK_MODEL_PATH}'")
    try:
        with open(network_path, 'rb') as f:
            NETWORK_MODEL = pickle.load(f)
        if not hasattr(NETWORK_MODEL, 'predict_proba'):
            raise RuntimeError(f"Network model from '{network_path}' does not expose 'predict_proba'.")
    except Exception as e:
        raise RuntimeError(f"Failed to load network model at '{network_path}': {e}") from e

    # Load structural analysis model
    structure_path = os.path.join(project_root, STRUCTURE_MODEL_PATH)
    if not os.path.isfile(structure_path):
        raise FileNotFoundError(f"Structure analysis model not found at '{STRUCTURE_MODEL_PATH}'")
    try:
        with open(structure_path, 'rb') as f:
            STRUCTURE_MODEL = pickle.load(f)
        if not hasattr(STRUCTURE_MODEL, 'predict_proba'):
            raise RuntimeError(f"Structure model from '{structure_path}' does not expose 'predict_proba'.")
    except Exception as e:
        raise RuntimeError(f"Failed to load structure model at '{structure_path}': {e}") from e
        
    # Load content analysis model
    content_path = os.path.join(project_root, CONTENT_MODEL_PATH)
    if not os.path.isfile(content_path):
        raise FileNotFoundError(f"Content analysis model not found at '{CONTENT_MODEL_PATH}'")
    try:
        with open(content_path, 'rb') as f:
            CONTENT_MODEL = pickle.load(f)
            # Validate model data structure
            if not isinstance(CONTENT_MODEL, dict) or 'models' not in CONTENT_MODEL or 'scaler' not in CONTENT_MODEL:
                raise RuntimeError("Content model format is invalid. Expected dictionary with 'models' and 'scaler'.")
    except Exception as e:
        raise RuntimeError(f"Failed to load content model at '{content_path}': {e}") from e


def validate_feature_module():
    """Verify that the `feature` module exposes `FeatureExtraction` class."""
    try:
        feature_mod = importlib.import_module('feature')
    except Exception as e:
        raise ImportError(f"Failed to import 'feature' module: {e}") from e

    if not hasattr(feature_mod, 'FeatureExtraction'):
        raise ImportError("'feature' module does not define 'FeatureExtraction' class.")


# Run validations at import/launch time so errors are visible early
try:
    validate_feature_module()
    validate_and_load_model()
except Exception:
    # Re-raise so Streamlit / the caller shows the error immediately
    raise

# Import feature extraction modules after validation
from feature import FeatureExtraction
from feature2 import FeatureExtraction2
from content_features import ContentFeatureExtractor

# Excel columns as required
EXCEL_COLUMNS = [
    "Application_ID",
    "Source of detection",
    "Identified Phishing/Suspected Domain Name",
    "Corresponding CSE Domain Name",
    "Critical Sector Entity Name",
    "Phishing/Suspected Domains (i.e. Class Label)",
    "Domain Registration Date",
    "Registrar Name",
    "Registrant Name or Registrant Organisation",
    "Registrant Country",
    "Name Servers",
    "Hosting IP",
    "Hosting ISP",
    "Hosting Country",
    "DNS Records (if any)",
    "Evidence file name",
    "Date of detection (DD-MM-YYYY)",
    "Time of detection (HH-MM-SS)",
    "Date of Post (If detection is from Source: social media)",
    "Remarks (If any)"
]

def get_model_predictions(url):
    """Get predictions from all three models for a given URL.
    
    Args:
        url: The URL to analyze
        
    Returns:
        dict: Dictionary containing individual model scores and ensemble score
    """
    # Extract features using all three feature extractors
    obj = FeatureExtraction(url)
    features = np.array(obj.getFeaturesList()).reshape(1, -1)
    
    # Get model predictions for network analysis
    network_prob = NETWORK_MODEL.predict_proba(features)[0][1]

    # Get model predictions for structural analysis
    obj2 = FeatureExtraction2(url)
    structure_features = np.array(obj2.extract_features()).reshape(1, -1)
    structure_prob = STRUCTURE_MODEL.predict_proba(structure_features)[0][1]
    
    # Get content features and predictions
    content_extractor = ContentFeatureExtractor(url)
    content_features = np.array(content_extractor.extract_features()).reshape(1, -1)
    scaled_features = CONTENT_MODEL['scaler'].transform(content_features)
    
    # Get predictions from all models in ensemble
    ensemble_predictions = []
    for model in CONTENT_MODEL['models']:
        prob = model.predict_proba(scaled_features)[0][1]
        ensemble_predictions.append(prob)
    
    # Average ensemble predictions for content model
    content_prob = sum(ensemble_predictions) / len(ensemble_predictions)
    
    # Combine all predictions
    visual_prob = (network_prob + structure_prob + content_prob) / 3
    
    results = {
        'Structural Intelligence': structure_prob,
        'Semantic Threat Detection': network_prob,
        'Content Behavior Analysis': content_prob,
        'Visual Brand Protection': visual_prob,
        'Ensemble Score': sum([network_prob, structure_prob, content_prob, visual_prob]) / 4
    }
    
    return results

def get_domain_info(url):
    """Extract domain registration and hosting info"""
    try:
        domain = urlparse(url).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        
        info = {
            'Domain Registration Date': '',
            'Registrar Name': '',
            'Registrant Country': '',
            'Name Servers': '',
            'Hosting IP': '',
            'Hosting Country': ''
        }
        
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                info['Domain Registration Date'] = creation_date.strftime("%d-%m-%Y")
            info['Registrar Name'] = w.registrar if hasattr(w, 'registrar') else ''
            info['Registrant Country'] = w.country if hasattr(w, 'country') else ''
        except:
            pass
        
        try:
            ns_answers = dns.resolver.resolve(domain, 'NS')
            info['Name Servers'] = ', '.join([str(r.target).rstrip('.') for r in ns_answers][:2])
        except:
            pass
        
        try:
            a_answers = dns.resolver.resolve(domain, 'A')
            ip = str(a_answers[0])
            info['Hosting IP'] = ip
            
            try:
                response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    info['Hosting Country'] = data.get('country', '')
            except:
                pass
        except:
            pass
        
        return info
    except:
        return {}

def main():
    st.set_page_config(page_title="Advanced URL Threat Detection", page_icon="🛡️", layout="wide")
    
    st.title("🛡️ Advanced Phishing URL Detection System")
    st.markdown("### Multi-Model Ensemble Detection with Deep Feature Analysis")
    
    # Sidebar with model information
    with st.sidebar:
        st.header("📊 Model Information")
        
        st.markdown("### Models Used:")
        
        st.markdown("""
        **1. Network Analysis** (25% weight)
        - Network behavior analysis
        - Domain reputation & WHOIS data
        
        **2. Structural Analysis** (25% weight)
        - URL structure examination
        - Pattern recognition
        
        **3. Content Analysis** (25% weight)
        - HTML/JavaScript analysis
        - Form & resource inspection
        - Behavioral feature detection
        
        **4. Visual Protection** (25% weight)
        - Combined pattern analysis
        - Structural correlation
        """)
        
        st.markdown("---")
        st.markdown("**Threshold:** 50% probability")
    
    # Main content tabs
    tab1, tab2 = st.tabs(["🔍 Single URL Analysis", "📁 Batch CSV Analysis"])
    
    # Tab 1: Single URL
    with tab1:
        st.subheader("Analyze Individual URL")
        url_input = st.text_input("Enter URL:", placeholder="https://example.com/path")
        
        col1, col2 = st.columns([1, 4])
        with col1:
            analyze_btn = st.button("🔎 Analyze", type="primary", use_container_width=True)
        with col2:
            show_details = st.checkbox("Show detailed domain information", value=False)
        
        if analyze_btn and url_input:
            with st.spinner("🔄 Extracting features..."):
                try:
                    # Get model predictions
                    predictions = get_model_predictions(url_input)
                    
                    st.success("✅ Analysis complete!")
                    
                    # Display results
                    st.markdown("---")
                    st.subheader("🎯 Detection Results")
                    
                    # Status
                    ensemble_score = predictions['Ensemble Score']
                    is_malicious = ensemble_score > 0.5
                    
                    col1, col2, col3 = st.columns([1, 1, 2])
                    with col1:
                        status_color = "🔴" if is_malicious else "🟢"
                        status_text = "PHISHING DETECTED" if is_malicious else "LEGITIMATE"
                        st.metric("Status", f"{status_color} {status_text}")
                    
                    with col2:
                        st.metric("Threat Level", f"{ensemble_score*100:.1f}%", 
                                 delta=f"{'High Risk' if ensemble_score > 0.7 else 'Medium Risk' if ensemble_score > 0.5 else 'Low Risk'}")
                    
                    with col3:
                        confidence = abs(ensemble_score - 0.5) * 2 * 100
                        st.metric("Detection Confidence", f"{confidence:.1f}%")
                    
                    # Individual model scores
                    st.markdown("#### 🤖 Individual Model Scores")
                    cols = st.columns(4)
                    
                    model_names = ['Structural Intelligence', 'Semantic Threat Detection', 
                                  'Content Behavior Analysis', 'Visual Brand Protection']
                    
                    for idx, (model_name, col) in enumerate(zip(model_names, cols)):
                        with col:
                            score = predictions[model_name] * 100
                            st.metric(
                                model_name.split()[0],
                                f"{score:.1f}%",
                                help=model_name
                            )
                    
                    # Ensemble visualization
                    st.markdown("#### 📊 Ensemble Score Breakdown")
                    chart_data = pd.DataFrame({
                        'Model': model_names + ['Ensemble'],
                        'Threat Score (%)': [predictions[m] * 100 for m in model_names] + [ensemble_score * 100]
                    })
                    st.bar_chart(chart_data.set_index('Model'), height=300)
                    
                    # Domain details if requested
                    if show_details:
                        with st.spinner("🔍 Fetching domain information..."):
                            domain_info = get_domain_info(url_input)
                            if domain_info:
                                st.markdown("#### 🌐 Domain Intelligence")
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.write("**Registration Details:**")
                                    st.text(f"Registration Date: {domain_info.get('Domain Registration Date', 'N/A')}")
                                    st.text(f"Registrar: {domain_info.get('Registrar Name', 'N/A')}")
                                    st.text(f"Country: {domain_info.get('Registrant Country', 'N/A')}")
                                with col2:
                                    st.write("**Hosting Information:**")
                                    st.text(f"IP Address: {domain_info.get('Hosting IP', 'N/A')}")
                                    st.text(f"Country: {domain_info.get('Hosting Country', 'N/A')}")
                                    st.text(f"Name Servers: {domain_info.get('Name Servers', 'N/A')[:50]}...")
                    
                except Exception as e:
                    st.error(f"❌ Error analyzing URL: {str(e)}")
                    st.info("Make sure the URL is accessible and properly formatted.")
    
    # Tab 2: CSV Upload
    with tab2:
        st.subheader("Batch Analysis from CSV")
        st.markdown("Upload a CSV file with columns: **Domain name** and **URL**")
        
        # Sample template
        with st.expander("📄 CSV Template"):
            sample_df = pd.DataFrame({
                'Domain name': ['example.com', 'suspicious-site.xyz', 'legitimate-bank.com'],
                'URL': ['https://example.com', 'http://suspicious-site.xyz/login', 'https://legitimate-bank.com']
            })
            st.dataframe(sample_df)
            st.download_button(
                "📥 Download Template",
                sample_df.to_csv(index=False),
                "url_template.csv",
                "text/csv"
            )
        
        uploaded_file = st.file_uploader("Choose CSV file", type=['csv'])
        
        if uploaded_file:
            try:
                df = pd.read_csv(uploaded_file)
                
                if 'Domain name' not in df.columns or 'URL' not in df.columns:
                    st.error("❌ CSV must contain 'Domain name' and 'URL' columns")
                else:
                    st.success(f"✅ Loaded {len(df)} URLs")
                    st.dataframe(df.head(10), use_container_width=True)
                    
                    col1, col2 = st.columns([1, 4])
                    with col1:
                        analyze_all = st.button("🚀 Analyze All", type="primary", use_container_width=True)
                    with col2:
                        fetch_domain_info = st.checkbox("Include domain information (slower)", value=False)
                    
                    if analyze_all:
                        results = []
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        for idx, row in df.iterrows():
                            status_text.text(f"Analyzing {idx + 1}/{len(df)}: {row['URL'][:50]}...")
                            
                            try:
                                predictions = get_model_predictions(row['URL'])
                                
                                result = {
                                    'Domain name': row['Domain name'],
                                    'URL': row['URL'],
                                    'Status': 'Malicious' if predictions['Ensemble Score'] > 0.5 else 'Safe',
                                    'Ensemble Score (%)': round(predictions['Ensemble Score'] * 100, 2),
                                    'Structural (%)': round(predictions['Structural Intelligence'] * 100, 2),
                                    'Semantic (%)': round(predictions['Semantic Threat Detection'] * 100, 2),
                                    'Content (%)': round(predictions['Content Behavior Analysis'] * 100, 2),
                                    'Visual (%)': round(predictions['Visual Brand Protection'] * 100, 2)
                                }
                                
                                if fetch_domain_info:
                                    domain_info = get_domain_info(row['URL'])
                                    result.update(domain_info)
                                
                                results.append(result)
                                
                            except Exception as e:
                                results.append({
                                    'Domain name': row['Domain name'],
                                    'URL': row['URL'],
                                    'Status': 'Error',
                                    'Ensemble Score (%)': 0,
                                    'Structural (%)': 0,
                                    'Semantic (%)': 0,
                                    'Content (%)': 0,
                                    'Visual (%)': 0
                                })
                            
                            progress_bar.progress((idx + 1) / len(df))
                        
                        status_text.empty()
                        results_df = pd.DataFrame(results)
                        
                        # Statistics
                        st.markdown("---")
                        st.subheader("📊 Detection Report")
                        
                        total = len(results_df)
                        malicious = len(results_df[results_df['Status'] == 'Malicious'])
                        safe = len(results_df[results_df['Status'] == 'Safe'])
                        errors = len(results_df[results_df['Status'] == 'Error'])
                        
                        col1, col2, col3, col4, col5 = st.columns(5)
                        col1.metric("📝 Total URLs", total)
                        col2.metric("🔴 Malicious", malicious)
                        col3.metric("🟢 Safe", safe)
                        col4.metric("⚠️ Errors", errors)
                        col5.metric("🎯 Detection Rate", f"{(malicious/(total-errors)*100):.1f}%" if total > errors else "0%")
                        
                        # Results table
                        st.markdown("#### 📋 Detailed Results")
                        
                        def highlight_status(row):
                            if row['Status'] == 'Malicious':
                                return ['background-color: #ffcccc'] * len(row)
                            elif row['Status'] == 'Safe':
                                return ['background-color: #ccffcc'] * len(row)
                            else:
                                return ['background-color: #ffffcc'] * len(row)
                        
                        styled_df = results_df.style.apply(highlight_status, axis=1)
                        st.dataframe(styled_df, use_container_width=True, height=400)
                        
                        # Download results
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        csv = results_df.to_csv(index=False)
                        st.download_button(
                            "📥 Download Results CSV",
                            csv,
                            f"url_detection_report_{timestamp}.csv",
                            "text/csv",
                            type="primary"
                        )
                        
                        # Score distribution
                        st.markdown("#### 📈 Threat Score Distribution")
                        st.bar_chart(results_df[results_df['Status'] != 'Error']['Ensemble Score (%)'].sort_values(ascending=False))
                        
            except Exception as e:
                st.error(f"❌ Error processing CSV: {str(e)}")

if __name__ == "__main__":
    main()