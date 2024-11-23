from pyspark import SparkConf, SparkContext

# Configuration with encryption enabled, but vulnerable to CVE-2019-10099
conf = SparkConf()
conf.set("spark.io.encryption.enabled", "true")  # Encryption enabled
conf.set("spark.maxRemoteBlockSizeFetchToMem", "64m")  # Example configuration

sc = SparkContext(conf=conf)

# Example data
data = [1, 2, 3, 4, 5]

# Using parallelize which could lead to unencrypted writes
rdd = sc.parallelize(data)

# Using broadcast which could lead to unencrypted writes
broadcast_var = sc.broadcast(rdd.collect())

# Using a Python UDF that could also lead to unencrypted writes
def multiply_by_two(x):
    return x * 2

result = rdd.map(multiply_by_two).collect()

print(result)

# Stop the Spark context
sc.stop()