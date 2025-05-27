# Fake URL Detector

A GUI-based application that helps users identify potentially malicious or fake URLs.

![Fake URL Detector](https://github.com/username/fake-url-detector/raw/main/screenshot.png)

## Features

- User-friendly graphical interface built with Tkinter
- Real-time URL analysis
- Multiple detection methods:
  - Protocol security check
  - Domain analysis
  - Typosquatting detection
  - Suspicious TLD identification
  - URL pattern recognition
  - Length and complexity assessment
- Risk scoring system
- Detailed analysis report
- Example URLs for testing

## How It Works

The Fake URL Detector uses various heuristics to analyze URLs and determine their potential risk:

1. **Protocol Analysis**: Checks if the URL uses secure HTTPS or insecure HTTP
2. **Domain Analysis**: Examines the domain for suspicious characteristics
3. **Typosquatting Detection**: Identifies domains that mimic popular brands with slight misspellings
4. **Pattern Recognition**: Looks for suspicious patterns in the URL structure
5. **Risk Scoring**: Assigns a risk score based on multiple factors

## Requirements

- Python 3.6+
- Tkinter (usually included with Python)

## Installation

1. Clone this repository:
```
git clone https://github.com/username/fake-url-detector.git
cd fake-url-detector
```

2. Run the application:
```
python fake_url_detector.py
```

## Usage

1. Enter a URL in the input field or select one of the example URLs
2. Click "Analyze URL" to start the analysis
3. Review the risk assessment and detailed analysis report
4. Click "Clear" to reset and analyze another URL

## Example URLs to Test

- Safe URLs:
  - https://www.google.com
  - https://www.amazon.com
  
- Suspicious URLs:
  - http://g00gle.com (typosquatting)
  - https://amaz0n.com-secure.info (brand impersonation)
  - https://paypal-secure.randomdomain.com (phishing attempt)

## Limitations

- The tool uses heuristic methods and may produce false positives or negatives
- It does not check the actual content of websites
- It cannot detect all types of malicious URLs
- This is an educational tool and should not replace proper security practices

## Future Improvements

- Website content analysis
- Domain age and reputation checking
- SSL certificate validation
- Malware database integration
- Browser extension version

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by various phishing detection techniques
- Built with Python and Tkinter
