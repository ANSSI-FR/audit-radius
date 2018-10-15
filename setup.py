#!/usr/bin/env python

from distutils.core import setup


def get_long_description():
    description = None

    try:
        with open("README.md") as f:
            description = f.read()
    except IOError:
        return None

    return description


setup(
    name="radius-audit",
    version=__import__('src.ra').VERSION,
    description="RADIUS configuration audit tool.",
    author="Pierre Lorinquer",
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    license="MIT",
    packages=[
        'src',
        'src.core',
        'src.utils'
    ],
    scripts=["ra"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ]
)
