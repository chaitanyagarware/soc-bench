from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="soc-parser",
    version="0.1.0",
    author="Chaitanya Vilas Garware",
    author_email="chaitanyagarware7@gmail.com",
    description="Fuzzy field extractor for SLM-based SOC log classifier evaluation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/chaitanyagarware/soc-parser",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "fuzzy": ["rapidfuzz>=3.0.0"],
    },
)
