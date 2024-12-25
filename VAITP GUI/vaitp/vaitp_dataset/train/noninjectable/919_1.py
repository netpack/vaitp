from datetime import datetime
from pydantic import BaseModel

class User(BaseModel):
    id: int
    signup_ts: datetime

# Corrected by parsing the datetime string correctly
user = User(id=1, signup_ts=datetime.fromisoformat('2023-10-27T10:00:00'))