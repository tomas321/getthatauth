#!/usr/bin/env python3

from setuptools import setup, find_packages


def readme():
    with open('README.md') as f:
        return f.read()


if __name__ == '__main__':
    setup(
        name='auth_logger',
        version='0.1.0',
        author='Tomas Bellus',
        author_email='tomas.bellus@gmail.com',
        long_description=readme(),
        description='Log HTTP authorization header field',
        classifiers=[
            'Programming Language :: Python :: 3'
        ],
        packages=find_packages(),
        install_requires=['scapy'],
        entry_points={
            'console_scripts': [
                'auth_logger = sniff_auth:main',
            ],
        }
    )
