from datetime import datetime
from pydantic import BaseModel

class User(BaseModel):
    id: int
    signup_ts: datetime

# This will cause high CPU usage due to the vulnerability
user = User(id=1, signup_ts='infinity')