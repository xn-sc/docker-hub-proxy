from sqlmodel import SQLModel, create_engine, text
from sqlalchemy.pool import StaticPool
from sqlalchemy import inspect
import logging

logger = logging.getLogger("database")

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

# check_same_thread=False is needed for SQLite with FastAPI/Threads
engine = create_engine(
    sqlite_url, 
    connect_args={"check_same_thread": False}, 
    poolclass=StaticPool
)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def upgrade_db():
    """Check for missing columns and add them (Auto-migration)."""
    try:
        inspector = inspect(engine)
        
        # ProxyNode upgrades
        if inspector.has_table("proxynode"):
            columns = [c["name"] for c in inspector.get_columns("proxynode")]
            with engine.connect() as conn:
                if "registry_type" not in columns:
                    logger.info("Migrating: Adding registry_type column to proxynode")
                    conn.execute(text("ALTER TABLE proxynode ADD COLUMN registry_type VARCHAR DEFAULT 'dockerhub'"))
                    
                if "route_prefix" not in columns:
                    logger.info("Migrating: Adding route_prefix column to proxynode")
                    conn.execute(text("ALTER TABLE proxynode ADD COLUMN route_prefix VARCHAR"))
                
                conn.commit()
    except Exception as e:
        logger.error(f"Migration failed: {e}")
