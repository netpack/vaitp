from pyspark import SparkConf, SparkContext

# Configuration to enable encryption
conf = SparkConf()
conf.set("spark.io.encryption.enabled", "true")
conf.set("spark.io.encryption.key", "your-encryption-key")  # Set your encryption key
conf.set("spark.maxRemoteBlockSizeFetchToMem", "64m")  # Example configuration

sc = SparkContext(conf=conf)

# Example data
data = [1, 2, 3, 4, 5]

# Using parallelize with encryption enabled
rdd = sc.parallelize(data)

# Using broadcast with encryption enabled
broadcast_var = sc.broadcast(rdd.collect())

# Perform actions on the RDD
result = rdd.map(lambda x: x * 2).collect()

print(result)

# Stop the Spark context
sc.stop()