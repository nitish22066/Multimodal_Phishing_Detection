from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from PIL import Image
import io
import numpy as np
import time

def capture_screenshot(url, target_size=(224, 224)):
    """Capture screenshot of a webpage and prepare it for model input."""
    # Configure Chrome options
    chrome_options = Options()
    chrome_options.add_argument('--headless')  # Run in headless mode
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--window-size=1920,1080')
    
    try:
        # Initialize the driver
        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=chrome_options
        )
        
        # Set page load timeout
        driver.set_page_load_timeout(10)
        
        # Navigate to URL
        driver.get(url)
        
        # Wait for page to load
        time.sleep(2)
        
        # Capture screenshot
        screenshot = driver.get_screenshot_as_png()
        
        # Close driver
        driver.quit()
        
        # Convert to PIL Image
        image = Image.open(io.BytesIO(screenshot))
        
        # Resize to target size
        image = image.resize(target_size)
        
        # Convert to numpy array and normalize
        img_array = np.array(image)
        img_array = img_array.astype('float32') / 255.0
        
        # Reshape for model input (add batch dimension)
        img_array = img_array.reshape(1, target_size[0], target_size[1], 3)
        
        return img_array
        
    except Exception as e:
        print(f"Error capturing screenshot: {str(e)}")
        return None