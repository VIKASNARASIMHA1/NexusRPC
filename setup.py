#!/usr/bin/env python3
"""
NexusRPC - Production-grade Custom RPC Framework
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="nexusrpc",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Enterprise-grade Custom RPC Framework with TLS, Auth, Service Discovery",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/nexusrpc",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Networking",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.1.0",
            "mypy>=1.5.0",
        ],
        "benchmark": [
            "grpcio>=1.59.0",
            "thrift>=0.16.0",
            "matplotlib>=3.7.0",
        ],
        "etcd": [
            "python-etcd>=0.4.5",
        ],
        "consul": [
            "requests>=2.31.0",
        ],
        "monitoring": [
            "prometheus-client>=0.17.0",
            "opentelemetry-api>=1.20.0",
            "opentelemetry-sdk>=1.20.0",
            "opentelemetry-exporter-jaeger>=1.20.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "nexusrpc-server=rpc.server_cli:main",
            "nexusrpc-client=examples.banking.client:main",
            "nexusrpc-benchmark=benchmarks.benchmark:main",
        ],
    },
)