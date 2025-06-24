from setuptools import setup, find_packages

setup(
    name="mycryptlib",
    version="1.0.0",
    packages=find_packages(),
    description="Advanced cryptographic library with topological transformations",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author="vd437",
    url="https://github.com/vd437/mycryptlib.git",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    python_requires='>=3.6',
)