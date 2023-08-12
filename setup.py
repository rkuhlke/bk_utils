from setuptools import setup, find_packages
import os, sys

with open('README.md', 'r') as fh:
    long_description = fh.read()
    
setup(
    name='bk-utils',
    version=os.popen('{} utilities/_version.py'.format(sys.executable)).read().rstrip(),
    author='Robert Kuhlke',
    author_email='bkuhlke@yahoo.com',
    description='I made this because I wanted to make my life easy on random shit',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(),
    py_modules=['cloud', 'slack', 'telegram', 'splunk', 'jira'],
    url='https://github.com/rkuhlke/utilities',
    python_requires='>=3.9',
    include_package_data=True
)