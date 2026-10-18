import os, sys
# Ensure the project root is in sys.path for imports, handling spaces in path.
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.append(project_root)
