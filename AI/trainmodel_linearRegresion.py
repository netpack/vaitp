from __future__ import absolute_import, division, print_function, unicode_literals

import numpy as np
import pandas as pd
import matplotlib as plt
from six.moves import urllib

import tensorflow.compat.v2.feature_column as fc
import tensorflow as tf

print("\n\nWelcome to VAITP AI - Supervised machine learning algorithm for vulnerability detection\n\n")

dftrain = pd.read_csv('train.csv')
dfeval = pd.read_csv('eval.csv')

y_train = dftrain.pop('vulnerable')
y_eval = dfeval.pop('vulnerable')



print("\nShape of the training dataset:")
print(dftrain.shape)
print("\nDescription of the training dataset:")
print(dftrain.describe())

print("\nShape of the evaluation dataset:")
print(dfeval.shape)
print("\nDescription of the evaluation dataset:")
print(dfeval.describe())



print("\nImported training values (head):")
print(dftrain.head())

print("\nImported evaluation values (head):")
print(dfeval.head())

CATEGORICAL_COLUMNS = ['code']
NUMERIC_COLUMNS = ['vulnerable']

feature_columns = []
for feature_name in CATEGORICAL_COLUMNS:
  vocabulary = dftrain[feature_name].unique()
  feature_columns.append(tf.feature_column.categorical_column_with_vocabulary_list(feature_name, vocabulary))

for feature_name in NUMERIC_COLUMNS:
  feature_columns.append(tf.feature_column.numeric_column(feature_name, dtype=tf.float32))


print("\nThe feature columns are:")
print(feature_columns)

#dftrain.vulnerable.hist(bins=20)
#dfeval.vulnerable.hist(bins=20)
#plt.pyplot.show()

#expected_vulnerable = dfeval.pop('vulnerable')
#print("\nExpected vulnerabilities:")
#print(expected_vulnerable)


def make_input_fn(data_df, label_df, num_epochs=10, shuffle=True, batch_size=32):
  def input_function():
    ds = tf.data.Dataset.from_tensor_slices((dict(data_df), label_df))
    if shuffle:
      ds = ds.shuffle(1000)
    ds = ds.batch(batch_size).repeat(num_epochs)
    return ds
  return input_function

train_input_fn = make_input_fn(dftrain, y_train)
eval_input_fn = make_input_fn(dfeval, y_eval, num_epochs=1, shuffle=False)

#create the model
linear_est = tf.estimator.LinearClassifier(feature_columns=feature_columns)

#train the model
linear_est.train(train_input_fn)
result = linear_est.evaluate(eval_input_fn)

clear_output()
print(result)


