from pathlib import Path
from setuptools import setup, find_packages

ROOT = Path(__file__).parent
README = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").exists() else ""

if __name__ == "__main__":
    setup(
        name="websecure-scanner",
        version="0.1.0",
        description="Hybrid web security scanner",
        long_description=README,
        long_description_content_type="text/markdown",
        python_requires=">=3.10",
        package_dir={"": "."},
        packages=find_packages(
            where=".",
            include=["*"],
            exclude=["tests*", "docs*", "dist*", "build*"]
        ),
        include_package_data=True,
        install_requires=[
            "regex>=2024.4.16",
            "requests>=2.32.0",
            "beautifulsoup4>=4.12.2",
            "lxml>=5.2.2",
            "tldextract>=5.1.2",
            "cryptography>=42.0.0",
            "jinja2>=3.1.0",
            "cvss>=3.2",
        ],
        extras_require={
            "js": ["playwright>=1.46.0"],
            "selenium": ["selenium>=4.23.1", "webdriver-manager>=4.0.2"],
            "speed": ["python-Levenshtein>=0.25.0"],
            "pdf": ["weasyprint>=61.0"],
            "bypass": ["tls-client>=1.0.1", "cloudscraper>=1.2.71"],
            "full": [
                "playwright>=1.46.0",
                "weasyprint>=61.0",
                "tls-client>=1.0.1",
                "cloudscraper>=1.2.71",
            ],
        },
    )
