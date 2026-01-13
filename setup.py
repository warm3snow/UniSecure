"""Setup configuration for UniSecure platform."""
from setuptools import setup, find_packages

setup(
    name="unisecure",
    version="0.1.0",
    description="All-in-one platform for end-to-end IT security — code, app, host, and container",
    author="UniSecure Team",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "pyyaml>=6.0",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "unisecure=unisecure.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
