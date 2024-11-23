from trytond.model import ModelSQL, ModelView, fields
from trytond.exceptions import AccessError

class User(ModelSQL, ModelView):
    "User "
    __name__ = 'res.user'

    # Define Many2Many field with access control
    groups = fields.Many2Many('res.group', 'user_group_rel', 'user_id', 'group_id', 
                               domain=[('id', 'in', User.get_accessible_groups())])

    @classmethod
    def get_accessible_groups(cls):
        # Only return groups that the current user has access to
        user = cls.get_current_user()
        return [group.id for group in user.groups]

    @classmethod
    def create(cls, values):
        # Custom create method to restrict group assignment
        if 'groups' in values:
            values['groups'] = cls.filter_accessible_groups(values['groups'])
        return super(User, cls).create(values)

    @classmethod
    def write(cls, ids, values):
        # Custom write method to restrict group assignment
        if 'groups' in values:
            values['groups'] = cls.filter_accessible_groups(values['groups'])
        return super(User, cls).write(ids, values)

    @classmethod
    def filter_accessible_groups(cls, groups):
        # Filter groups to ensure user can only assign accessible groups
        accessible_groups = cls.get_accessible_groups()
        return [group for group in groups