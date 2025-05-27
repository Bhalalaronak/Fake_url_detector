#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import re
import urllib.parse
import socket
import ssl
from datetime import datetime
import threading

class FakeURLDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("Fake URL Detector")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Set theme colors
        self.bg_color = "#f0f0f0"
        self.header_color = "#2c3e50"
        self.button_color = "#3498db"
        self.warning_color = "#e74c3c"
        self.safe_color = "#2ecc71"
        self.neutral_color = "#f39c12"
        
        self.root.configure(bg=self.bg_color)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.root, bg=self.header_color, height=60)
        header_frame.pack(fill=tk.X)
        
        header_label = tk.Label(header_frame, text="Fake URL Detector", 
                               font=("Arial", 18, "bold"), bg=self.header_color, fg="white")
        header_label.pack(pady=15)
        
        # Main content
        content_frame = tk.Frame(self.root, bg=self.bg_color)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # URL Input
        input_frame = tk.Frame(content_frame, bg=self.bg_color)
        input_frame.pack(fill=tk.X, pady=10)
        
        url_label = tk.Label(input_frame, text="Enter URL to check:", 
                            font=("Arial", 12), bg=self.bg_color)
        url_label.pack(anchor=tk.W)
        
        self.url_entry = tk.Entry(input_frame, font=("Arial", 12), width=50)
        self.url_entry.pack(fill=tk.X, pady=5)
        self.url_entry.bind("<Return>", lambda event: self.analyze_url())
        
        # Example URLs
        examples_frame = tk.Frame(content_frame, bg=self.bg_color)
        examples_frame.pack(fill=tk.X, pady=5)
        
        examples_label = tk.Label(examples_frame, text="Examples to try:", 
                                 font=("Arial", 10), bg=self.bg_color)
        examples_label.pack(anchor=tk.W)
        
        examples = [
            "https://www.google.com",
            "http://g00gle.com",
            "https://amaz0n.com-secure.info",
            "https://paypal-secure.randomdomain.com"
        ]
        
        for example in examples:
            example_btn = tk.Button(examples_frame, text=example, 
                                   command=lambda e=example: self.set_example(e),
                                   bg=self.bg_color, borderwidth=0, cursor="hand2")
            example_btn.pack(anchor=tk.W)
        
        # Buttons
        button_frame = tk.Frame(content_frame, bg=self.bg_color)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.analyze_button = tk.Button(button_frame, text="Analyze URL", 
                                      command=self.analyze_url, bg=self.button_color,
                                      fg="white", font=("Arial", 12), padx=15, pady=5)
        self.analyze_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = tk.Button(button_frame, text="Clear", 
                                    command=self.clear_results, bg=self.button_color,
                                    fg="white", font=("Arial", 12), padx=15, pady=5)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(content_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, pady=10)
        
        # Results
        results_frame = tk.Frame(content_frame, bg=self.bg_color)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Summary result
        self.result_label = tk.Label(results_frame, text="", font=("Arial", 14, "bold"), 
                                   bg=self.bg_color)
        self.result_label.pack(fill=tk.X, pady=5)
        
        # Detailed results
        details_label = tk.Label(results_frame, text="Analysis Details:", 
                               font=("Arial", 12), bg=self.bg_color)
        details_label.pack(anchor=tk.W, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, 
                                                   width=70, height=15, font=("Arial", 10))
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def set_example(self, example):
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, example)
    
    def clear_results(self):
        self.url_entry.delete(0, tk.END)
        self.result_label.config(text="")
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)
        self.progress_var.set(0)
        self.status_var.set("Ready")
    
    def update_progress(self, value):
        self.progress_var.set(value)
        self.root.update_idletasks()
    
    def add_detail(self, text, risk_level=None):
        self.details_text.config(state=tk.NORMAL)
        
        if risk_level == "high":
            self.details_text.insert(tk.END, text + "\n", "high_risk")
            self.details_text.tag_configure("high_risk", foreground=self.warning_color)
        elif risk_level == "medium":
            self.details_text.insert(tk.END, text + "\n", "medium_risk")
            self.details_text.tag_configure("medium_risk", foreground=self.neutral_color)
        elif risk_level == "low":
            self.details_text.insert(tk.END, text + "\n", "low_risk")
            self.details_text.tag_configure("low_risk", foreground=self.safe_color)
        else:
            self.details_text.insert(tk.END, text + "\n")
        
        self.details_text.config(state=tk.DISABLED)
        self.details_text.see(tk.END)
    
    def analyze_url(self):
        url = self.url_entry.get().strip()
        
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL to analyze.")
            return
        
        # Clear previous results
        self.result_label.config(text="")
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)
        
        # Start analysis in a separate thread to keep UI responsive
        self.status_var.set("Analyzing URL...")
        self.analyze_button.config(state=tk.DISABLED)
        
        analysis_thread = threading.Thread(target=self.perform_analysis, args=(url,))
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def perform_analysis(self, url):
        try:
            # Initialize risk score
            risk_score = 0
            max_score = 100
            
            # Add http:// if no protocol specified
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            self.add_detail(f"Analyzing URL: {url}")
            self.add_detail("Analysis started at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.add_detail("-" * 50)
            
            # Parse URL
            self.update_progress(10)
            parsed_url = urllib.parse.urlparse(url)
            
            # Check protocol
            self.update_progress(20)
            if parsed_url.scheme == 'http':
                risk_score += 15
                self.add_detail("❌ Using insecure HTTP protocol", "high")
            else:
                self.add_detail("✅ Using secure HTTPS protocol", "low")
            
            # Check domain
            self.update_progress(30)
            domain = parsed_url.netloc
            
            # Check for IP address instead of domain name
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                risk_score += 20
                self.add_detail("❌ URL uses IP address instead of domain name", "high")
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.xyz', '.info', '.top', '.club', '.tk', '.ml', '.ga', '.cf']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                risk_score += 10
                self.add_detail(f"⚠️ Domain uses suspicious TLD: {domain}", "medium")
            
            # Check for typosquatting (common brand names with slight misspellings)
            self.update_progress(40)
            common_brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix']
            domain_without_tld = domain.split('.')[0]
            
            for brand in common_brands:
                # Check for brand name with numbers (g00gle)
                if re.search(f"{brand[0]}[0-9]+{brand[1:]}", domain_without_tld, re.IGNORECASE):
                    risk_score += 15
                    self.add_detail(f"❌ Possible typosquatting detected: {domain} (replacing letters with numbers)", "high")
                
                # Check for brand name with slight misspelling
                if brand not in domain_without_tld and self.levenshtein_distance(brand, domain_without_tld) <= 2:
                    risk_score += 15
                    self.add_detail(f"❌ Possible typosquatting detected: {domain} (similar to {brand})", "high")
            
            # Check for excessive subdomains
            self.update_progress(50)
            subdomain_count = len(domain.split('.')) - 2
            if subdomain_count > 2:
                risk_score += 10
                self.add_detail(f"⚠️ Excessive subdomains detected: {domain}", "medium")
            
            # Check for suspicious URL patterns
            self.update_progress(60)
            suspicious_patterns = [
                'login', 'signin', 'account', 'secure', 'update', 'verify',
                'wallet', 'confirm', 'banking', 'security'
            ]
            
            path = parsed_url.path.lower()
            
            for pattern in suspicious_patterns:
                if pattern in path and any(brand in domain for brand in common_brands):
                    risk_score += 5
                    self.add_detail(f"⚠️ URL contains suspicious term: {pattern}", "medium")
            
            # Check for excessive URL length
            self.update_progress(70)
            if len(url) > 100:
                risk_score += 5
                self.add_detail(f"⚠️ URL is unusually long ({len(url)} characters)", "medium")
            
            # Check for URL redirects
            self.update_progress(80)
            if '@' in domain:
                risk_score += 20
                self.add_detail("❌ URL contains @ symbol which can lead to redirection", "high")
            
            # Check for excessive query parameters
            self.update_progress(90)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            if len(query_params) > 5:
                risk_score += 5
                self.add_detail(f"⚠️ URL contains many query parameters ({len(query_params)})", "medium")
            
            # Final risk assessment
            self.update_progress(100)
            self.add_detail("-" * 50)
            self.add_detail(f"Risk Score: {risk_score}/{max_score}")
            
            # Set final result
            if risk_score >= 30:
                result_text = f"⚠️ SUSPICIOUS URL (Risk Score: {risk_score}/{max_score})"
                self.root.after(0, lambda: self.result_label.config(
                    text=result_text, fg=self.warning_color))
            else:
                result_text = f"✅ LIKELY SAFE URL (Risk Score: {risk_score}/{max_score})"
                self.root.after(0, lambda: self.result_label.config(
                    text=result_text, fg=self.safe_color))
            
            self.add_detail("Analysis completed at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
        except Exception as e:
            self.add_detail(f"Error during analysis: {str(e)}", "high")
        
        finally:
            self.root.after(0, lambda: self.status_var.set("Analysis complete"))
            self.root.after(0, lambda: self.analyze_button.config(state=tk.NORMAL))
    
    def levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

def main():
    root = tk.Tk()
    app = FakeURLDetector(root)
    root.mainloop()

if __name__ == "__main__":
    main()
