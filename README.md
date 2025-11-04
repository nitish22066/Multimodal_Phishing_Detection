# Phishing URL Detection System

A multi-model ensemble system for detecting phishing URLs using network analysis, structural patterns, and content behavior.

## Setup Instructions

1. Create a virtual environment:
```bash
python3 -m venv .venv
```

2. Activate the virtual environment:
```bash
# On Linux/Mac:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

Run the Streamlit app:
```bash
streamlit run app.py
```

The application will be available at http://localhost:8501

## Model Components

The system uses three different models for comprehensive phishing detection:

1. Network Analysis Model
   - Analyzes network characteristics and domain reputation
   - Located at: Models/model_network_analysis.pkl

2. Structure Analysis Model
   - Examines URL structure and patterns
   - Located at: Models/phishing_structure_analysis.pkl

3. Content Analysis Model
   - Analyzes webpage content and behavior
   - Located at: Models/phishing_page_content_analysis.pkl
     
4. Visual Analysis Model
   - Analyzes screenshot of website
   - Located at: Models/phishing_detector_screenshots.pkl
## Troubleshooting

1. If you see XGBoost warnings about serialized models, these can be safely ignored.

2. If you get ModuleNotFoundError:
   - Make sure you've activated the virtual environment
   - Try reinstalling the dependencies: `pip install -r requirements.txt`

3. If models fail to load:
   - Verify all .pkl files are in the correct locations
   - Check file permissions
   - Ensure you're using Python 3.8 or later

4. For SSL/Connection errors:
   - Check your internet connection
   - Verify the URL is accessible
   - Try with a different URL to confirm if it's a specific website issue
