from setuptools import setup, find_packages

setup(
    name='netgrep',
    version='0.3.5',
    author='CSIRT Foundry / Chris Horsley',
    author_email='chris.horsley@csirtfoundry.com',
    scripts=['bin/netgrep'],
    url='http://pypi.python.org/pypi/netgrep/',
    packages=find_packages(),
    install_requires=[
        'publicsuffix>=1.0.0',
        'httplib2>=0.6.0',
        'BulkWhois>=0.2.1',
        'adns-python>=1.2.1',
        'argparse',
    ],
    download_url='https://github.com/csirtfoundry/netgrep/tarball/master',
    license='LICENSE.txt',
    description='Grep-like filter for files based on country codes and ASN',
    long_description=open('README.txt').read(),
 )
