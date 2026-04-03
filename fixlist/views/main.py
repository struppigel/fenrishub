"""
Main views module - refactored into domain-specific modules.

All view functions have been moved to focused domain-specific modules:
- auth.py: Authentication and user account views
- uploads.py: Uploaded log management views  
- fixlists.py: Fixlist management views
- analyzer.py: Log analyzer views and APIs
- snippets.py: Fixlist snippet management views
- rules.py: Classification rule management views
- utils.py: Shared utility functions

The __init__.py package file re-exports all views for backward compatibility,
ensuring that existing code using `from fixlist.views import function_name`
or `from fixlist import views; views.function_name` continues to work.
"""

# Re-export render for backward compatibility with test patches
from django.shortcuts import render

__all__ = ['render']

