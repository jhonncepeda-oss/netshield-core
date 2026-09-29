import sys
import uvicorn
from src.presentation.cli.app import run_cli

def main():
    # Force UTF-8 encoding for Windows console to support rich banner characters
    if sys.stdout.encoding != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')
        
    if len(sys.argv) > 1 and sys.argv[1] == "api":
        print("Starting NetShield Core API...")
        uvicorn.run("src.presentation.api.main:app", host="0.0.0.0", port=8000, reload=True)
    else:
        # Run CLI by default if no 'api' command is passed
        run_cli()

if __name__ == "__main__":
    main()
