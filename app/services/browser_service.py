import os
import time
import hashlib
from urllib.parse import urlparse
import requests
import cv2
import numpy as np

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from webdriver_manager.firefox import GeckoDriverManager

from config import Config

class BrowserService:
    """Service handling headless browser rendering, page stabilization, and screenshots."""

    @staticmethod
    def get_firefox_options():
        """Configure headless Firefox options."""
        options = FirefoxOptions()
        options.add_argument("--headless")
        options.add_argument("--window-size=1366,900")
        options.page_load_strategy = "eager"
        return options

    @staticmethod
    def create_driver():
        """Create a configured Firefox WebDriver instance."""
        try:
            service = FirefoxService(GeckoDriverManager().install())
            driver = webdriver.Firefox(service=service, options=BrowserService.get_firefox_options())
        except Exception:
            service = FirefoxService()
            driver = webdriver.Firefox(service=service, options=BrowserService.get_firefox_options())

        driver.set_page_load_timeout(Config.PAGE_LOAD_TIMEOUT)
        driver.set_script_timeout(10)
        return driver

    @staticmethod
    def normalize_route_path(url):
        """Normalize URL path for route-level comparison."""
        try:
            path = (urlparse(url).path or "/").rstrip("/")
            if path == "" or path.lower() == "/index":
                path = "/"
            return path.lower()
        except Exception:
            return "/"

    @staticmethod
    def is_same_route(monitored_url, loaded_url):
        """Check whether the browser landed on the expected route."""
        try:
            monitored = urlparse(monitored_url)
            loaded = urlparse(loaded_url)
            return (
                monitored.scheme.lower() == loaded.scheme.lower()
                and monitored.netloc.lower() == loaded.netloc.lower()
                and BrowserService.normalize_route_path(monitored_url) == BrowserService.normalize_route_path(loaded_url)
            )
        except Exception:
            return False

    @staticmethod
    def has_auth_config():
        """Return True when authenticated scanning is enabled and credentials exist."""
        return (
            Config.AUTH_ENABLED
            and bool(Config.AUTH_USERNAME and Config.AUTH_PASSWORD and Config.AUTH_LOGIN_URL)
        )

    @staticmethod
    def perform_login(driver):
        """Log in to target application using configured credentials."""
        if not BrowserService.has_auth_config():
            return False

        try:
            driver.get(Config.AUTH_LOGIN_URL)
            BrowserService.wait_for_page_stable(driver, timeout=Config.PAGE_LOAD_TIMEOUT)

            if Config.AUTH_USERNAME_SELECTOR:
                user_el = driver.find_element(By.CSS_SELECTOR, Config.AUTH_USERNAME_SELECTOR)
            else:
                user_el = driver.find_element(
                    By.CSS_SELECTOR,
                    "input[type='text'], input[type='email'], input[name*='user' i], input[name*='email' i]"
                )

            if Config.AUTH_PASSWORD_SELECTOR:
                pass_el = driver.find_element(By.CSS_SELECTOR, Config.AUTH_PASSWORD_SELECTOR)
            else:
                pass_el = driver.find_element(By.CSS_SELECTOR, "input[type='password']")

            user_el.clear()
            user_el.send_keys(Config.AUTH_USERNAME)
            pass_el.clear()
            pass_el.send_keys(Config.AUTH_PASSWORD)

            if Config.AUTH_SUBMIT_SELECTOR:
                submit_el = driver.find_element(By.CSS_SELECTOR, Config.AUTH_SUBMIT_SELECTOR)
            else:
                submit_el = driver.find_element(By.CSS_SELECTOR, "button[type='submit'], input[type='submit'], button")

            submit_el.click()
            BrowserService.wait_for_page_stable(driver, timeout=Config.PAGE_LOAD_TIMEOUT)
            return True
        except Exception as e:
            print(f"⚠️ Auth login failed: {e}")
            return False

    @staticmethod
    def inject_stability_observer(driver):
        """Inject JavaScript MutationObserver to track active DOM changes."""
        script = """
        (function(){
            window.__tampertrace_last_mutation_ts = Date.now();
            if (window.__tampertrace_mutation_observer_installed) { return true; }
            window.__tampertrace_mutation_observer_installed = true;
            const observer = new MutationObserver(function(mutations) {
                window.__tampertrace_last_mutation_ts = Date.now();
            });
            try {
                observer.observe(document, { attributes: true, childList: true, subtree: true });
            } catch(e) {
                try { observer.observe(document.body, { attributes: true, childList: true, subtree: true }); } catch(err) {}
            }
            window.__tampertrace_initial_height = document.body ? document.body.scrollHeight : (document.documentElement ? document.documentElement.scrollHeight : 0);
            return true;
        })();
        """
        try:
            driver.execute_script(script)
        except Exception:
            pass

    @staticmethod
    def wait_for_page_stable(driver, timeout=30, dom_stable_seconds=Config.DOM_STABLE_SECONDS, network_idle_seconds=Config.NETWORK_IDLE_SECONDS):
        """Wait until readyState is complete and DOM mutations cease."""
        start = time.time()
        last_height = None
        stable_since = None

        BrowserService.inject_stability_observer(driver)

        while True:
            try:
                ready = driver.execute_script("return document.readyState")
            except Exception:
                ready = None

            try:
                last_mutation = driver.execute_script("return window.__tampertrace_last_mutation_ts || Date.now();")
            except Exception:
                last_mutation = int(time.time() * 1000)

            try:
                height = driver.execute_script("return (document.body ? document.body.scrollHeight : (document.documentElement ? document.documentElement.scrollHeight : 0))")
            except Exception:
                height = last_height

            now_ms = int(time.time() * 1000)
            time_since_mutation = (now_ms - int(last_mutation)) / 1000.0

            if last_height is None:
                last_height = height
                stable_since = time.time()
            else:
                if height == last_height:
                    elapsed = time.time() - stable_since
                else:
                    last_height = height
                    stable_since = time.time()
                    elapsed = 0.0

            ready_ok = (ready == "complete")
            no_recent_mutation = (time_since_mutation >= dom_stable_seconds)
            height_ok = ((time.time() - stable_since) >= dom_stable_seconds)

            if ready_ok and no_recent_mutation and height_ok:
                time.sleep(network_idle_seconds)
                return True

            if time.time() - start > timeout:
                return False

            time.sleep(0.5)

    @staticmethod
    def wait_for_images_loaded(driver, timeout=10):
        """Wait until all <img> elements are fully loaded."""
        start = time.time()
        while True:
            try:
                all_loaded = driver.execute_script("""
                    return Array.from(document.images).every(img => img.complete && img.naturalWidth > 0);
                """)
                if all_loaded:
                    return True
            except Exception:
                pass

            if time.time() - start > timeout:
                return False

            time.sleep(0.5)

    @classmethod
    def capture_initial_baseline(cls, url):
        """Capture page baseline for initial onboarding in /add_url."""
        driver = None
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        try:
            driver = cls.create_driver()
            driver.get(url)
            
            try:
                html_source = driver.execute_script("return document.documentElement.outerHTML;")
            except Exception:
                html_source = driver.page_source

            filename = f"{hashlib.md5(url.encode()).hexdigest()}.png"
            screenshot_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            driver.save_screenshot(screenshot_path)

            html_hash = hashlib.sha256(html_source.encode("utf-8", errors="ignore")).hexdigest()
            return html_source, html_hash, screenshot_path
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

    @classmethod
    def capture_page(cls, url, timeout=Config.PAGE_LOAD_TIMEOUT):
        """
        Load page robustly with stabilization and capture HTML + screenshot.
        Returns: (html_content, screenshot_path, is_success, final_url)
        """
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        driver = None
        screenshot_path = None
        final_url = url

        try:
            driver = cls.create_driver()
            driver.get(url)
            final_url = driver.current_url

            # Redirect handling
            if final_url and not cls.is_same_route(url, final_url):
                if cls.has_auth_config() and cls.perform_login(driver):
                    driver.get(url)
                    final_url = driver.current_url

            # Stabilization
            stable = cls.wait_for_page_stable(driver, timeout=timeout)
            if not stable:
                time.sleep(2)

            cls.wait_for_images_loaded(driver, timeout=8)
            time.sleep(1)

            try:
                html_content = driver.execute_script("return document.documentElement.outerHTML;")
            except Exception:
                html_content = driver.page_source

            # Freeze animations for deterministic screenshot
            try:
                driver.execute_script("""
                    document.querySelectorAll("img").forEach(img => {
                        img.style.animation = "none";
                        img.style.transition = "none";
                    });
                """)
            except Exception:
                pass

            filename = f"{hashlib.md5(url.encode()).hexdigest()}_{int(time.time())}.png"
            screenshot_path = os.path.join(Config.UPLOAD_FOLDER, filename)
            driver.save_screenshot(screenshot_path)

            return html_content, screenshot_path, True, final_url

        except (TimeoutException, WebDriverException, Exception) as e:
            print(f"⚠️ Selenium capture failed for {url}: {e}")

            # Fallback via requests
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                resp = requests.get(url, timeout=10, headers=headers)
                resp.raise_for_status()
                html_content = resp.text

                filename = f"fallback_{hashlib.md5(url.encode()).hexdigest()}_{int(time.time())}.png"
                screenshot_path = os.path.join(Config.UPLOAD_FOLDER, filename)
                img = np.zeros((600, 1000, 3), dtype=np.uint8)
                cv2.putText(img, "Screenshot unavailable (requests fallback)", (20, 300),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
                cv2.imwrite(screenshot_path, img)

                return html_content, screenshot_path, False, resp.url
            except Exception as e2:
                print(f"❌ Fallback requests also failed for {url}: {e2}")
                return None, None, False, final_url

        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass
