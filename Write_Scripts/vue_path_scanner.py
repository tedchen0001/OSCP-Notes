#!/usr/bin/env python3
"""
Vue Path Scanner - A tool for scanning and testing web paths in Vue.js applications.
This tool supports JavaScript rendering.
"""

import time
from playwright.sync_api import sync_playwright
import re
from datetime import datetime
import argparse
import os

def save_to_log(path, content):
    """
    Save detailed rendered content to a log file.
    
    Args:
        path: The tested path
        content: The rendered HTML content
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"render_log_{timestamp}.txt"
    
    with open(filename, "a", encoding='utf-8') as f:
        f.write(f"\n{'='*50}\n")
        f.write(f"Path: {path}\n")
        f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Content:\n{content}\n")
        f.write(f"{'='*50}\n")

def save_result_log(filepath, result):
    """
    Save scan results to a specified log file.
    
    Args:
        filepath: Path to the log file
        result: Dictionary containing scan result data
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, "a", encoding='utf-8') as f:
        status_text = f"{result['status']} {'(Redirected to login)' if result['is_login_page'] else ''}"
        f.write(f"Path: {result['path']} | Status: {status_text} | Size: {result['size']} bytes\n")

def try_path(page, path, base_url, enable_logging=False, delay=1):
    """
    Test a single path and analyze its response.
    
    Args:
        page: Playwright page object
        path: Path to test
        base_url: Base URL of the target application
        enable_logging: Whether to save detailed logs
        delay: Delay between requests in seconds
    
    Returns:
        Dictionary containing test results or None if test failed
    """
    url = base_url + path
    
    try:
        print(f"Testing path: {path}", end='\r')
        response = page.goto(url)
        # Wait for Vue rendering
        page.wait_for_selector('#app', timeout=5000)
        time.sleep(delay)
        
        # Get rendered content
        app_content = page.evaluate('document.querySelector("#app").innerHTML')
        
        if app_content and app_content.strip():  # If content found and not empty
            content_size = len(app_content.strip())
            
            # Get current URL
            current_url = page.url
            
            # Check if redirected to login page
            is_login_page = 'login' in current_url.lower()
            
            status_code = response.status if response else (302 if is_login_page else 200)
            
            print(f"Path: {path} | Status Code: {status_code} | Content Size: {content_size} bytes")
            
            # Save detailed log if enabled
            if enable_logging:
                save_to_log(path, app_content.strip())
            
            return {
                'path': path,
                'status': status_code,
                'size': content_size,
                'is_login_page': is_login_page
            }
        return None
    
    except Exception as e:
        print(f"Error with path {path}: {str(e)}")
        return None

def main():
    """Main function handling argument parsing and scan execution."""
    parser = argparse.ArgumentParser(
        description='Vue.js Path Scanner - Test web paths with JavaScript rendering support'
    )
    parser.add_argument('--target-url', type=str, required=True,
                      help='Base URL of the target application (e.g., "https://example.com/app/#/")')
    parser.add_argument('--paths-file', type=str, required=True,
                      help='File containing paths to test (one path per line)')
    parser.add_argument('--baseline-paths', type=str,
                      help='Comma-separated list of paths to test first (e.g., "login,setting,dashboard")')
    parser.add_argument('--request-delay', type=float, default=1.0,
                      help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--content-log', action='store_true',
                      help='Enable logging of rendered HTML content')
    parser.add_argument('--result-log', type=str,
                      help='Path to save result log (e.g., "logs/results.txt")')
    args = parser.parse_args()
    
    # Load paths file
    try:
        with open(args.paths_file, 'r') as f:
            paths = [line.strip() for line in f]
    except FileNotFoundError:
        print("Paths file not found!")
        return
    
    # Process baseline paths
    baseline_paths = []
    if args.baseline_paths:
        try:
            baseline_paths = [p.strip() for p in args.baseline_paths.split(',') if p.strip().isalnum()]
            if not baseline_paths:
                print("Warning: No valid baseline paths provided")
            else:
                print(f"Baseline paths to test first: {', '.join(baseline_paths)}")
                
            # Check for invalid inputs
            original_paths = args.baseline_paths.split(',')
            invalid_paths = [p.strip() for p in original_paths if not p.strip().isalnum()]
            if invalid_paths:
                print(f"Warning: Ignored invalid paths: {', '.join(invalid_paths)}")
            
            # Move baseline paths to the beginning
            for path in reversed(baseline_paths):
                if path in paths:
                    paths.remove(path)
                paths.insert(0, path)
        except Exception as e:
            print(f"Error processing baseline paths: {str(e)}")
            print("Using paths file without baseline paths")
            baseline_paths = []
    
    # Print initial information
    print(f"Target URL: {args.target_url}")
    print(f"Loaded {len(paths)} paths from paths file")
    print(f"Content logging is {'enabled' if args.content_log else 'disabled'}")
    print(f"Request delay: {args.request_delay} seconds")
    if args.result_log:
        print(f"Result log will be saved to: {args.result_log}")
    
    # Start scanning
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        start_time = time.time()
        results = []
        for path in paths:
            result = try_path(page, path, args.target_url, args.content_log, args.request_delay)
            if result:
                results.append(result)
                if args.result_log:
                    save_result_log(args.result_log, result)
        
        browser.close()
    
    # Print summary
    print("\nSummary:")
    print(f"Total attempts: {len(paths)}")
    print(f"Successful requests (with content in app div): {len(results)}")
    print(f"Time taken: {time.time() - start_time:.2f} seconds")
    
    if results:
        print("\nResults sorted by content size:")
        results.sort(key=lambda x: x['size'], reverse=True)
        for result in results:
            status_text = f"{result['status']} {'(Redirected to login)' if result['is_login_page'] else ''}"
            print(f"Path: {result['path']} | Status: {status_text} | Size: {result['size']} bytes")
            print("-" * 80)

if __name__ == "__main__":
    main()