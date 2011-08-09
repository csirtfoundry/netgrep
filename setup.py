from distutils.core import setup

setup(
    name='netgrep',
    version='0.2.1',
    author='CSIRT Foundry / Chris Horsley',
    author_email='chris.horsley@csirtfoundry.com',
    packages=['netgrep'],
    scripts=['bin/netgrep'],
    url='http://pypi.python.org/pypi/netgrep/',
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
