class ModelStorage:
    def __init__(self, model_name):
        self.model_name = model_name
        self.data = {}  # Simulate database storage

    def create(self, values, user_id):
        new_id = len(self.data) + 1
        self.data[new_id] = values
        return new_id

    def read(self, ids, fields, user_id):
        results = []
        for record_id in ids:
            if record_id in self.data:
                results.append({field: self.data[record_id].get(field) for field in fields})
            else:
                results.append(None)
        return results

    def write(self, ids, values, user_id):
      for record_id in ids:
        if record_id in self.data:
            self.data[record_id].update(values)
      return True

    def delete(self, ids, user_id):
      for record_id in ids:
        if record_id in self.data:
          del self.data[record_id]
      return True

    def copy(self, ids, default_values, user_id):
        new_ids = []
        for record_id in ids:
            if record_id in self.data:
                new_id = len(self.data) + 1
                new_record = self.data[record_id].copy()
                new_record.update(default_values)
                self.data[new_id] = new_record
                new_ids.append(new_id)
        return new_ids

class User:
    def __init__(self, user_id, name, groups=None):
        self.id = user_id
        self.name = name
        self.groups = groups if groups else []

class Group:
    def __init__(self, group_id, name):
        self.id = group_id
        self.name = name

class Model:
    def __init__(self, model_storage):
        self.storage = model_storage

    def create(self, values, user_id):
        return self.storage.create(values, user_id)

    def read(self, ids, fields, user_id):
        return self.storage.read(ids, fields, user_id)
    
    def write(self, ids, values, user_id):
       return self.storage.write(ids, values, user_id)

    def delete(self, ids, user_id):
       return self.storage.delete(ids, user_id)
    
    def copy(self, ids, default_values, user_id):
        return self.storage.copy(ids, default_values, user_id)

# Example setup
user_storage = ModelStorage('user')
group_storage = ModelStorage('group')
user_group_storage = ModelStorage('user_group')


user_model = Model(user_storage)
group_model = Model(group_storage)
user_group_model = Model(user_group_storage)


# Create some users and groups
user1_id = user_model.create({'name': 'user1'}, 1)
user2_id = user_model.create({'name': 'user2'}, 1)
group1_id = group_model.create({'name': 'group1'}, 1)
group2_id = group_model.create({'name': 'group2'}, 1)

# User1 is in group1
user_group_model.create({'user': user1_id, 'group': group1_id},1)

#Vulnerability example: User2 can modify user_groups table
user_group_model.write([1], {'group': group2_id}, user2_id) # User2 modifies the Many2Many field to add User1 to group2


print("User Groups after manipulation: ", user_group_model.read([1], ["user", "group"], user2_id))