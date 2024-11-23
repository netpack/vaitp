from trytond.model import ModelSQL, ModelView, fields

class User(ModelSQL, ModelView):
    "User  "
    __name__ = 'res.user'

    # Vulnerable Many2Many field without access control
    groups = fields.Many2Many('res.group', 'user_group_rel', 'user_id', 'group_id')

    @classmethod
    def create(cls, values):
        # Directly creating a user with groups without restriction
        return super(User, cls).create(values)

    @classmethod
    def write(cls, ids, values):
        # Directly writing to user groups without restriction
        return super(User, cls).write(ids, values)

    @classmethod
    def delete(cls, ids):
        # Deleting users without any privilege checks
        return super(User, cls).delete(ids)