from setuptools import setup, find_packages

with open("guardrail_framework/README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="guardrail-framework",
    version="1.0.0",
    author="Enterprise AI Safety Team",
    description="Unified guardrail abstraction layer for multi-backend AI safety",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourorg/guardrail-framework",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: System :: Monitoring",
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "typing-extensions>=4.0.0",
        "dataclasses-json>=0.5.0",
    ],
    extras_require={
        "server": [
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
            "pydantic>=2.0.0",
        ],
        "observability": [
            "prometheus-client>=0.18.0",
            "python-json-logger>=2.0.0",
        ],
        "distributed": [
            "redis>=5.0.0",
            "sqlalchemy>=2.0.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "guardrail-framework=guardrail_framework.cli:main",
        ],
    },
)
