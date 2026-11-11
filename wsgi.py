"""WSGI entry point for production servers (gunicorn on Render).

The project has both an `app/` package and an `app.py` module, so
"gunicorn app:app" would import the package instead of app.py. This file
loads app.py explicitly by path, leaving app.py itself unchanged.
"""
import importlib.util
import os

_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
_spec = importlib.util.spec_from_file_location("sentinel_ledger_main", _path)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

app = _module.app
