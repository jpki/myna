import sys
from . import app

def main():
    app.cli()

if __name__ == '__main__':
    sys.argv[0] = 'jpki'
    main()
