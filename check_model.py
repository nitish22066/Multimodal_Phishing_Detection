import pickle

# Load content model
with open('Models/phishing_page_content_analysis.pkl', 'rb') as f:
    model = pickle.load(f)
    
print("Model type:", type(model))
print("Available methods:", dir(model))