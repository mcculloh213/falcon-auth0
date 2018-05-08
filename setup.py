from setuptools import setup, find_packages
from codecs import open
from os import path

root = path.abspath(path.dirname(__file__))

with open(path.join(root, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    # Application Name:
    name='falcon_auth0',

    # Version Number:
    version='1.0.1',

    # Classifiers
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],

    # Keywords
    keywords='falcon authorization auth0',

    # Application Author Details:
    author='H.D. "Chip" McCullough IV',
    author_email='hdmccullough.work@gmail.com',

    # Packages:
    packages=find_packages(exclude=['documentation', 'scripts', 'test']),

    # Details:
    url='https://github.com/mcculloh213/alchemist-stack',
    project_urls={
        'Documentation': 'https://github.com/mcculloh213/falcon-auth0',
        #'Funding': 'https://github.com/mcculloh213/falcon-auth0',
        'Source': 'https://github.com/mcculloh213/falcon-auth0',
        'Issue Tracker': 'https://github.com/mcculloh213/falcon-auth0/issues'
    },
    license='MIT',
    description='Auth0 Authorization Middleware for The Falcon Web Framework',
    long_description=long_description,
    long_description_content_type='text/markdown',

    # Dependent Packages (Distributions):
    install_requires=[
        'falcon',
        'python-jose-cryptodome',
        'six'
    ],

    # Requires Python Version:
    python_requires='>=3'
)