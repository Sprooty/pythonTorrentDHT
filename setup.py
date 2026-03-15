#! /usr/bin/env python
import os
from setuptools import setup, find_packages

VERSION = "1.0.1"

if __name__ == "__main__":
    with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
        README = readme.read()

    setup(
        name="pythontorrentdht",
        version=VERSION,
        packages=find_packages(),
        include_package_data=True,
        license='GPLv3',
        description="Full implementation of the BitTorrent mainline DHT",
        long_description=README,
        long_description_content_type='text/markdown',
        author='Aaron Spratt',
        author_email='github@sprooty.com',
        classifiers=[
            'Development Status :: 4 - Beta',
            'Intended Audience :: Developers',
            'Intended Audience :: Science/Research',
            'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.10',
            'Programming Language :: Python :: 3.11',
            'Programming Language :: Python :: 3.12',
            'Programming Language :: Python :: 3.13',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'Topic :: Communications :: File Sharing'
        ],
        python_requires='>=3.10',
        install_requires=["datrie >= 0.7", "netaddr >= 0.7.12"],
        url='https://github.com/Sprooty/pythonTorrentDHT/',
        download_url="https://github.com/Sprooty/pythonTorrentDHT/releases/latest",
        zip_safe=True,
    )
