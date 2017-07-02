import os

from .file_storage import PROJECT_CFG_DIR
from peewee import *

PROJECT_DB_FILE = os.path.join(PROJECT_CFG_DIR, 'database')
PROJECT_DB = SqliteDatabase(PROJECT_DB_FILE)

class BaseModel(Model):
    class Meta:
        database = PROJECT_DB
