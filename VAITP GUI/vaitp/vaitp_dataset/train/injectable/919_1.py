from datetime import datetime
from pydantic import BaseModel, validator, ValidationError

class User(BaseModel):
    id: int
    signup_ts: datetime

    @validator('signup_ts', pre=True)
    def check_datetime(cls, value):
        if value in {'infinity', 'inf', float('inf'), '-infinity', '-inf', -float('inf')}:
            raise ValueError("Invalid value for datetime: cannot be infinity")
        return value

# Example usage
try:
    user = User(id=1, signup_ts='infinity')
except ValidationError as e:
    print(e)