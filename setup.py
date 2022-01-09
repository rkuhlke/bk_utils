from setuptools import setup, find_packages

REQUIRED_PACKAGES=[
    "boto3",
    "botocore",
    "requests"
]

setup(
    name="utilities",
    version="1.0",
    packages=find_packages(),
    url="https://github.com/rkuhlke/utilities",
    install_requires=REQUIRED_PACKAGES,
    author="Robert Kuhlke",
    author_email="bkuhlke@yahoo.com",
    description="Utilities Library"
)