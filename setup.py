from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="bugpredict-ai",
    version="1.0.0",
    author="BugPredict AI Contributors",
    author_email="contact@bugpredict.ai",
    description="AI-Powered Vulnerability Prediction for Bug Bounty Hunters",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bugpredict-ai",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/bugpredict-ai/issues",
        "Documentation": "https://github.com/yourusername/bugpredict-ai/docs",
        "Source Code": "https://github.com/yourusername/bugpredict-ai",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "bugpredict=src.cli.main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "bugpredict": [
            "config/*.yaml",
            "web/templates/*.html",
            "web/static/css/*.css",
            "web/static/js/*.js",
        ],
    },
)
