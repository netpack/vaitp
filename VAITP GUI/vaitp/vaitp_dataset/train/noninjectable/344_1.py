from dask.distributed import LocalCluster, Client

# Create a LocalCluster (vulnerable configuration)
cluster = LocalCluster()
client = Client(cluster)

print("Dask client created with external access")