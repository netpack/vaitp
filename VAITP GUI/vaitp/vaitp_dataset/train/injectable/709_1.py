from pyspark import SparkConf, SparkContext
import os
import secrets

# Generate a strong encryption key
encryption_key = secrets.token_hex(32)


# Configuration to enable encryption
conf = SparkConf()
conf.set("spark.io.encryption.enabled", "true")
conf.set("spark.io.encryption.key", encryption_key)
conf.set("spark.maxRemoteBlockSizeFetchToMem", "64m")  # Example configuration
conf.set("spark.ssl.enabled", "true")
conf.set("spark.ssl.keyStore", "keystore.jks")
conf.set("spark.ssl.keyStorePassword", "keystore_password")
conf.set("spark.ssl.trustStore", "truststore.jks")
conf.set("spark.ssl.trustStorePassword", "truststore_password")



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