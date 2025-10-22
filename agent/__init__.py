from pathlib import Path

# Base directory for the agent package. Use this to build absolute paths
# to packaged resources so code doesn't depend on the current working directory.
BASE_DIR = Path(__file__).resolve().parent

def resource_path(*parts):
    """Return an absolute Path to a resource inside the agent package."""
    return BASE_DIR.joinpath(*parts)
