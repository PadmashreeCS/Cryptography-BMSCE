# routes/__init__.py
# ==================
# Makes the 'routes' directory a Python package so that
# 'from routes.main_routes import main_bp' works from app.py.
# Blueprints are imported individually in app.py — nothing is
# re-exported from here.
