import marshmallow as m
from marshmallow import fields
from marshmallow.exceptions import ValidationError

class UserSchema(m.Schema):
    name = fields.Str(required=True)
    email = fields.Email(required=True)
    age = fields.Int(required=True, validate=lambda n: n >= 0)


def create_user(data):
    try:
        schema = UserSchema()
        result = schema.load(data)
    except ValidationError as err:
        return {"error": err.messages}, 400
    return {"message": f"User {result['name']} created"}, 201

if __name__ == "__main__":
    test_data_ok = {"name": "John", "email": "test@example.com", "age": 30}
    test_data_bad = {"name": "John", "email": "test", "age": -30}

    print(create_user(test_data_ok))
    print(create_user(test_data_bad))
