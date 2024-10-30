from dask.distributed import LocalCluster, Client

# Create a LocalCluster (patched configuration)
cluster = LocalCluster(ip='127.0.0.1')  # Bind to localhost
client = Client(cluster)

print("Dask client created with restricted access to localhost")