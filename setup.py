"""
SOC-EATER v2 - Desktop Application Setup

Install:
    pip install -e .
    
Run:
    soc-eater-desktop
    # or
    python -m soc_eater_v2.desktop_app
"""

from setuptools import setup, find_packages

setup(
    name="soc-eater-v2",
    version="2.0.0",
    description="AI-Powered Security Operations Center - Desktop Application",
    author="SOC-EATER Team",
    url="https://github.com/soc-eater/soc-eater-v2",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.11",
    install_requires=[
        "fastapi>=0.110",
        "uvicorn[standard]>=0.27",
        "pydantic>=2.6",
        "pyyaml>=6.0",
        "jinja2>=3.1",
        "python-multipart>=0.0.9",
        "google-generativeai>=0.8.3",
        "pillow>=10.0",
        "dpkt>=1.9.8",
        "pyqt6>=6.6",
    ],
    entry_points={
        "console_scripts": [
            "soc-eater-desktop=soc_eater_v2.desktop_app:main",
        ],
    },
    extras_require={
        "dev": [
            "pytest>=7.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
        ],
        "web": [
            "gradio>=4.0",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Security Professionals",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: Mac OS X",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="security, soc, ai, gemini, incident-response, threat-intel",
    project_urls={
        "Source": "https://github.com/soc-eater/soc-eater-v2",
        "Issues": "https://github.com/soc-eater/soc-eater-v2/issues",
    },
)
