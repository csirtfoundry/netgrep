#from distutils.core import setup
from setuptools import setup, find_packages

setup(
    name='netgrep',
    version='0.3.0',
    author='CSIRT Foundry / Chris Horsley',
    author_email='chris.horsley@csirtfoundry.com',
    scripts=['bin/netgrep'],
    url='http://pypi.python.org/pypi/netgrep/',
    packages=find_packages(),
    #packages=['netgrep'],
    install_requires=[
        'publicsuffix',
        'httplib2',
        'BulkWhois',
    ],
    download_url='https://github.com/csirtfoundry/netgrep/tarball/master',
    license='LICENSE.txt',
    description='Grep-like filter for files based on country codes and ASN',
    long_description=open('README.txt').read(),
 )
