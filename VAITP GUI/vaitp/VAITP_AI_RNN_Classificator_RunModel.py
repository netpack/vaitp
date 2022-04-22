import sys
from tensorflow import keras
import tensorflow as tf
import tensorflow_datasets as tfds
from tensorflow.keras import layers
from tensorflow.keras import losses
from tensorflow.keras import utils
from tensorflow.keras.layers import TextVectorization
import tensorflow_datasets as tfds
import tensorflow_text as tf_text
import pathlib
import time
from datetime import timedelta

time_start = time.time()


#define function to predict the label with the most score
def get_string_labels(predicted_scores_batch):
  predicted_int_labels = tf.argmax(predicted_scores_batch, axis=1)
  predicted_labels = tf.gather(raw_train_ds.class_names, predicted_int_labels)
  return predicted_labels



print("Starting VAITP AI RNN Classicator RunModel...")


#Vars
path_to_exported_models = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/exported_ai_models/"
model_name = "vaitp_classificator_model_190_240_7_0.82_2022_04_20_21_04.tfv"
input_newcode = "VAITP_AI_RNN_Classificator_newInput.vaitp"


#Load the model
model_p = path_to_exported_models+model_name
model = keras.models.load_model(model_p)

print(f'Model Loaded: {model_name}')

print(f'Model Summary: {model.summary()}')



#Get new input
with open(input_newcode,'r') as fin:
    lines = fin.readlines()

final_input_string = []
for line in lines:
    final_input_string.append(line)

print(f'New code vector: {final_input_string}')




dataset_dir = pathlib.Path("../vaitp/vaitp_dataset")
train_dir = dataset_dir/'train'
batch_size = 10
seed = 4
raw_train_ds = utils.text_dataset_from_directory(
    train_dir,
    batch_size=batch_size,
    validation_split=0.2,
    subset='training',
    seed=seed)





predicted_scores = model.predict(final_input_string)

predicted_labels = get_string_labels(predicted_scores)

for input, label in zip(final_input_string, predicted_labels):
  print("\ncode: ", input)
  print("\npredicted label: ", label.numpy())


time_now = time.time()
time_delta = time_now-time_start
print(f'AI RNN Classificator Model finished in {timedelta(seconds=time_delta)}')

