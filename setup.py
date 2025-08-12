# setup.py
from setuptools import setup, find_packages

setup(
    name="mr_prince",
    version="2025.1",
    description="mr_prince — Advanced self-contained CLI Port Scanner (PORTSCANNER-AI-2025-CLI)",
    author="Prince",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "mr=mr_prince.cli:main",
        ],
    },
    include_package_data=True,
    license="MIT",
)
