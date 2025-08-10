"""
SQLAlchemy declarative base
"""
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# Models will be imported when needed to avoid circular imports