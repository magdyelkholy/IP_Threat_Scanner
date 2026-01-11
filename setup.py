"""
IP Threat Scanner - Setup Script
Install with: pip install .
"""

from setuptools import setup, find_packages
import os

# Read README
long_description = ""
if os.path.exists("README.md"):
    with open("README.md", "r", encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="ip-threat-scanner",
    version="1.0.0",
    author="Magdy Elkhouly",
    author_email="",
    description="Scan IP addresses using VirusTotal and AbuseIPDB APIs - Created by Magdy Elkhouly",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/magdyelkhouly/ip-threat-scanner",
    
    py_modules=["ip_scanner"],
    
    install_requires=[
        "customtkinter>=5.2.0",
        "requests>=2.28.0",
    ],
    
    entry_points={
        "console_scripts": [
            "ip-scanner=ip_scanner:main",
        ],
        "gui_scripts": [
            "ip-scanner-gui=ip_scanner:main",
        ],
    },
    
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet",
    ],
    
    python_requires=">=3.8",
    
    keywords="ip scanner virustotal abuseipdb security threat intelligence",
)
