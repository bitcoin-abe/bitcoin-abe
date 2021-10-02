from distutils.core import setup

execfile("Abe/version.py")

setup(
    name         = "Abe",
    version      = __version__,
    requires     = ['Crypto.Hash'],
    packages     = ['Abe', 'Abe.Chain'],
    package_data = {'Abe': ['htdocs/*']},
    author       = "John Tobey",
    author_email = "jtobey@john-edwin-tobey.org",
    url          = "https://github.com/bitcoin-abe/bitcoin-abe",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: Financial and Insurance Industry',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Topic :: Database :: Front-Ends',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Internet :: WWW/HTTP :: WSGI',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'Topic :: Office/Business :: Financial',
        'Topic :: Security :: Cryptography',
        #'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    description  = "Abe: a free block chain browser for Bitcoin-based currencies.",
    long_description = """Abe reads the Bitcoin block chain from disk, loads
it into a database, indexes it, and provides a web interface to search
and navigate it.  Abe works with several Bitcoin-derived currencies,
including Namecoin and LiteCoin.

Abe draws inspiration from Bitcoin Block Explorer (BBE,
http://blockexplorer.com/) and seeks some level of compatibility with
it but uses a completely new implementation.""",
    )
