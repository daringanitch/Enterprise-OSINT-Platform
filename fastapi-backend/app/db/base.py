"""
SQLAlchemy declarative base
"""
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# Import all models so they are registered with SQLAlchemy
from app.models import *  # noqa: F403,F401