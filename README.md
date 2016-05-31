# dbxfs

Yo! Welcome to dbxfs. This is how you should dev:

1. Get virtualenv (either use brew, apt-get, yum, or pip)
2. Create your virtualenv (make sure to use Python 3):

        $ virtualenv -p python3 env

3. Source it:

        $ source env/bin/activate

4. Now install package (in development mode, symlinks installed package to current directory)

        $ python setup.py develop

5. Run executable (this will run the module at "dbxfs/main.py"):

        $ dbxfs
