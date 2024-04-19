import sys
import os
import collections
import pathlib
import numpy as np
import ast, re

import datetime
import time
from time import gmtime, strftime
from datetime import timedelta

import shutil, random

from pprint import pprint

import pandas as pd
import sklearn.metrics
import autosklearn.classification
from sklearn.model_selection import train_test_split

#Save starting time for benchmark
time_start = time.time()

#select the dataset directory
data_path = "vaitp_dataset_ast"
#dataset_dir = pathlib.Path("../vaitp/vaitp_dataset_ast")

data_path_inj = str(data_path)+"/injectable"
data_path_noninj = str(data_path)+"/noninjectable"


#Count non-injectable and injectable files
train_dir_inj_count = len([n for n in os.listdir(data_path_inj) if os.path.isfile(os.path.join(data_path_inj, n))])
train_dir_noninj_count = len([n for n in os.listdir(data_path_noninj) if os.path.isfile(os.path.join(data_path_noninj, n))])

print(f'Total files in injectable dataset: {train_dir_inj_count}\nTotal files in non-injectable dataset: {train_dir_noninj_count}')

#Vectors for the text codes and labels
texts = []
labels = []

#Loop the files and appends to text and labels to vectors
for label in os.listdir(data_path):
    sub_path = os.path.join(data_path, label)
    for filename in os.listdir(sub_path):
        with open(os.path.join(sub_path, filename), 'r') as f:
            texts.append(f.read())
        labels.append(label)

#Create a panda dataframe with the vectors
df = pd.DataFrame({'code': texts, 'label': labels})

#Split into training and testing dataframes
X_train, X_test, y_train, y_test = train_test_split(df['code'], df['label'], test_size=0.2, random_state=42)

#convert the Series to a Dataframe
X_train = X_train.to_frame()
X_test = X_test.to_frame()

#Create an autosklearn Classifier or Regressor depending the task at hand
automl = autosklearn.classification.AutoSklearnClassifier(
    time_left_for_this_task=60,
    per_run_time_limit=30,
)

#Fit the automl model
automl.fit(X_train, y_train, dataset_name="VAITP")  

#Calculate benchmarks
time_now = time.time()
time_delta = time_now-time_start
print(f'Autosklearn finished in {timedelta(seconds=time_delta)}')

#View models found by Autosklearn
print('Models found by Autosklearn:')
print(automl.leaderboard())



#View final ensemble score
print('Final Autosklearn ensemble accuracy score:')
predictions = automl.predict(X_test)
print("Accuracy score:", sklearn.metrics.accuracy_score(y_test, predictions))


print('AutoML models:')
#pPrint final ensemble constructed by auto-sklearn
pprint(automl.show_models(), indent=4)


print("\nVAITP Autosklearn finished correctly.")