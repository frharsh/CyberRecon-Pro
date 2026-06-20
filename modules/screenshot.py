"""
CyberRecon Pro - Screenshot Capture Module
Uses Playwright for headless browser screenshot capture.
Falls back to requests-based method if Playwright is unavailable.
"""

import os
import subprocess


def take_screenshot(url: str, filepath: str) -> tuple:
    """
    Capture a screenshot of the given URL.
    Returns: (success: bool, message: str)
    """
    # Try Playwright first
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox',
                      '--disable-dev-shm-usage', '--disable-gpu']
            )
            ctx  = browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent=(
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/120.0.0.0 Safari/537.36'
                ),
                ignore_https_errors=True,
            )
            page = ctx.new_page()
            try:
                page.goto(url, timeout=20000, wait_until='domcontentloaded')
                page.wait_for_timeout(2000)
                page.screenshot(path=filepath, full_page=False)
                browser.close()
                return True, f'Screenshot captured: {os.path.basename(filepath)}'
            except Exception as e:
                browser.close()
                return False, f'Page navigation failed: {str(e)}'

    except ImportError:
        pass
    except Exception as e:
        # Playwright installed but browser not downloaded
        if 'Executable' in str(e) or 'browser' in str(e).lower():
            # Try installing playwright browsers
            try:
                subprocess.run(
                    'playwright install chromium', shell=True,
                    capture_output=True, timeout=120
                )
                # Retry
                return take_screenshot(url, filepath)
            except Exception:
                pass
        return False, f'Playwright error: {str(e)}'

    # Fallback: try Selenium
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service

        chrome_opts = Options()
        chrome_opts.add_argument('--headless')
        chrome_opts.add_argument('--no-sandbox')
        chrome_opts.add_argument('--disable-dev-shm-usage')
        chrome_opts.add_argument('--disable-gpu')
        chrome_opts.add_argument('--window-size=1280,800')

        driver = webdriver.Chrome(options=chrome_opts)
        try:
            driver.get(url)
            import time; time.sleep(2)
            driver.save_screenshot(filepath)
            driver.quit()
            return True, f'Screenshot captured via Selenium: {os.path.basename(filepath)}'
        except Exception as e:
            driver.quit()
            return False, f'Selenium navigation failed: {str(e)}'

    except ImportError:
        pass
    except Exception as e:
        return False, f'Selenium error: {str(e)}'

    # Last fallback: create a placeholder image
    return _create_placeholder(url, filepath)


def _create_placeholder(url: str, filepath: str) -> tuple:
    """Create a placeholder image when no browser is available."""
    try:
        from PIL import Image, ImageDraw, ImageFont
        img  = Image.new('RGB', (1280, 800), color=(6, 11, 20))
        draw = ImageDraw.Draw(img)

        # Draw border
        draw.rectangle([2, 2, 1277, 797], outline=(0, 212, 255), width=2)

        # Title
        draw.text((640, 200), 'CyberRecon Pro', fill=(0, 212, 255), anchor='mm')
        draw.text((640, 280), 'Screenshot Capture', fill=(124, 58, 237), anchor='mm')
        draw.text((640, 380), f'URL: {url[:80]}', fill=(201, 209, 217), anchor='mm')
        draw.text((640, 440), 'Install Playwright: pip install playwright', fill=(255, 170, 0), anchor='mm')
        draw.text((640, 470), 'Then run: playwright install chromium', fill=(255, 170, 0), anchor='mm')

        img.save(filepath, 'PNG')
        return True, 'Placeholder screenshot created (install Playwright for real screenshots)'
    except ImportError:
        # Write minimal PNG
        with open(filepath, 'wb') as f:
            # Minimal 1x1 gray PNG
            f.write(bytes([
                137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,
                0,0,0,1,0,0,0,1,8,0,0,0,0,58,126,155,85,0,0,0,
                10,73,68,65,84,120,156,98,102,0,0,0,2,0,1,232,
                221,122,204,0,0,0,0,73,69,78,68,174,66,96,130
            ]))
        return False, 'Screenshot capture requires Playwright or Pillow. Please install dependencies.'
