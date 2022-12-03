def vaitp_function(self, tree):
    if self.secured.get(tree.id) is not None:
        return Symbol(self.secured.get(tree.id))

    return tree
