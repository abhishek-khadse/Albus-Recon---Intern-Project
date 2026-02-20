
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

class ReconResult(Base):
    __tablename__ = "recon_results"
    
    id = Column(Integer, primary_key=True)
    url = Column(String(500), nullable=False)
    status_code = Column(Integer)
    title = Column(String(500))
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
