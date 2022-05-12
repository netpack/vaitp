import sys
import os
import collections
import pathlib
import numpy as np

import tensorflow_datasets as tfds
import tensorflow as tf

from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras import losses
from tensorflow.keras import utils
from tensorflow.keras.layers import TextVectorization

import tensorflow_datasets as tfds
import tensorflow_text as tf_text

import keras
import keras.backend as K

tfds.disable_progress_bar()

import matplotlib.pyplot as plt

import datetime
import time
from time import gmtime, strftime
from datetime import timedelta


time_start = time.time()



#Get params
#Model epochs
if int(sys.argv[1]) < 1:
  exit('please input model epochs value as argv1 [50 7 0]')

#Layer density
if int(sys.argv[2]) < 1:
  exit('please input Layer Density value as argv3 [50 7 0]')

#Dropout
if float(sys.argv[3]) < 0:
  exit('please input dropout value as argv4 [50 7 0.2]')

#Setup logs for tensorboard
log_dir = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/tf_logs/" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
tensorboard_callback = keras.callbacks.TensorBoard(
    log_dir=log_dir,
    histogram_freq=0,  # How often to log histogram visualizations
    embeddings_freq=0,  # How often to log embedding visualizations
    update_freq="epoch",
) 


#enable some graph ploting
#def plot_graphs(history, metric):
#  plt.plot(history.history[metric])
#  plt.plot(history.history['val_'+metric], '')
#  plt.xlabel("Epochs")
#  plt.ylabel(metric)
#  plt.legend([metric, 'val_'+metric])

#select the dataset directory
dataset_dir = pathlib.Path("../vaitp/vaitp_dataset_ast")
#print("\nDataset directory listing:")
#print(list(dataset_dir.iterdir()))

#tain directory
train_dir = dataset_dir/'train'
#print("\nTrain dataset directory listing:")
#print(list(train_dir.iterdir()))

#print sample file
#print("\nSample file content read:")
#sample_file = train_dir/'vulnerable/2.txt'
#with open(sample_file) as f:
#  print(f.read())



#Create a full trainig set for final predictions
raw_train_ds_full = utils.text_dataset_from_directory(
    train_dir,
    batch_size=228
    )


#Create trainig set  [should be around 20% of the set]
batch_size = 45#228#64
seed = 4
raw_train_ds = utils.text_dataset_from_directory(
    train_dir,
    batch_size=batch_size,
    validation_split=0.25,
    subset='training',
    seed=seed)

#show what the lables correspond to
for i, label in enumerate(raw_train_ds.class_names):
  print("Label", i, "corresponds to", label)


#iterate randomly on the data to feel it better
#for text_batch, label_batch in raw_train_ds.take(1):
#  for i in range(10):
#    print("code: ", text_batch.numpy()[i])
#    print("Label:", label_batch.numpy()[i])

#create a validation set.
raw_val_ds = utils.text_dataset_from_directory(
    train_dir,
    batch_size=batch_size,
    validation_split=0.25,
    subset='validation',
    seed=seed)

test_dir = dataset_dir/'test'

#create a test set.
raw_test_ds = utils.text_dataset_from_directory(
    test_dir,
    batch_size=batch_size)


#prepare the datase for training
    #standarization: removes punctuation and html elements to simplify the dataset
    #tokenization: splits strings into tokens
    #vectorization: converts tokens into numbers to be fed into the NN

VOCAB_SIZE = 500000
MAX_SEQUENCE_LENGTH = 450

#Binary vectorization builds a "bag full of words" model
binary_vectorize_layer = TextVectorization(
    max_tokens=VOCAB_SIZE,
    output_mode='binary')

#int mode: a 1D convolutional neural network
int_vectorize_layer = TextVectorization(
    max_tokens=VOCAB_SIZE,
    output_mode='int',
    output_sequence_length=MAX_SEQUENCE_LENGTH)

# Make a text-only dataset (without labels), then call `TextVectorization.adapt`
train_text = raw_train_ds.map(lambda text, labels: text)
binary_vectorize_layer.adapt(train_text)
int_vectorize_layer.adapt(train_text)

#def vectorization functions
def binary_vectorize_text(text, label):
  text = tf.expand_dims(text, -1)
  return binary_vectorize_layer(text), label

def int_vectorize_text(text, label):
  text = tf.expand_dims(text, -1)
  return int_vectorize_layer(text), label

# Retrieve a batch of codes and labels from the dataset
text_batch, label_batch = next(iter(raw_train_ds_full))
#first_code, first_label = text_batch[0], label_batch[0]
#print("\ncode: ", first_code)
#print("\nlabel: ", first_label)

#print binary and int versions
#print("'binary' vectorized code:",
#      binary_vectorize_text(first_code, first_label)[0])
#print("'int' vectorized code:",
#      int_vectorize_text(first_code, first_label)[0])

'''
#apply textVectorization layers
binary_train_ds = raw_train_ds.map(binary_vectorize_text)
binary_val_ds = raw_val_ds.map(binary_vectorize_text)
binary_test_ds = raw_test_ds.map(binary_vectorize_text)
'''
int_train_ds = raw_train_ds.map(int_vectorize_text)
int_val_ds = raw_val_ds.map(int_vectorize_text)
int_test_ds = raw_test_ds.map(int_vectorize_text)

#prefetch data to buffer
AUTOTUNE = tf.data.AUTOTUNE

def configure_dataset(dataset):
  return dataset.cache().prefetch(buffer_size=AUTOTUNE)
'''
binary_train_ds = configure_dataset(binary_train_ds)
binary_val_ds = configure_dataset(binary_val_ds)
binary_test_ds = configure_dataset(binary_test_ds)
'''
int_train_ds = configure_dataset(int_train_ds)
int_val_ds = configure_dataset(int_val_ds)
int_test_ds = configure_dataset(int_test_ds)

'''
#train the model for argv epochs
binary_model = tf.keras.Sequential([layers.Dense(int(sys.argv[2]))])

binary_model.compile(
    loss=losses.SparseCategoricalCrossentropy(from_logits=True),
    optimizer='adam',
    metrics=['accuracy'],
    )

history = binary_model.fit(
    binary_train_ds, 
    validation_data=binary_val_ds, 
    epochs=int(sys.argv[1]),
    #callbacks=[tensorboard_callback]
    )
'''



#use the 'int' vectorized layer to make a 1D convolutional neural network (1D are good for text)
def create_model(vocab_size, num_labels):
  model = tf.keras.Sequential([
      layers.Embedding(vocab_size, 64, mask_zero=True),
      layers.Conv1D(64, 5, padding="same", activation="relu", strides=2),
      #layers.ConvLSTM1D(64, return_sequences=True),
      layers.GlobalMaxPooling1D(),
      layers.Dropout(float(sys.argv[3])),
      #layers.Bidirectional(tf.keras.layers.LSTM(64,  return_sequences=True)),
      #layers.Bidirectional(tf.keras.layers.LSTM(32)),
      #layers.Dense(3, activation='relu'),
      #layers.Dense(num_labels*2)
      layers.Dense(num_labels)
  ])
  return model

# `vocab_size` is `VOCAB_SIZE + 1` since `0` is used additionally for padding.

int_model = create_model(vocab_size=VOCAB_SIZE + 1, num_labels=3)
int_model.compile(
    loss=losses.SparseCategoricalCrossentropy(from_logits=True),
    optimizer='adam',
    metrics=['accuracy'])
history = int_model.fit(int_train_ds, validation_data=int_val_ds, epochs=int(sys.argv[1]), callbacks=[tensorboard_callback])

'''
#compare the two models:
print("\nlinear model on binary vectorized data:")
print(binary_model.summary())

#sumarise ConvNet model:
print("\nconvNet model on int vectorized data:")
print(int_model.summary())

#evaluate models accuracy:
binary_loss, binary_accuracy = binary_model.evaluate(binary_test_ds)
'''
int_loss, int_accuracy = int_model.evaluate(int_test_ds)

#print("\nBag of Words model accuracy: {:2.2%}".format(binary_accuracy))
print("\nConv1D model accuracy: {:2.2%}".format(int_accuracy))

#print("\n\nmodel trained. exporting the model...\n\n")

#export the model
'''
export_model = tf.keras.Sequential(
    [binary_vectorize_layer, binary_model,
     layers.Activation('sigmoid')])
'''

export_model = tf.keras.Sequential(
    [int_vectorize_layer, int_model,
     layers.Activation('sigmoid')])

#print("\n")


'''
#Categorical True Positives
class CategoricalTruePositives(keras.metrics.Metric):
    def __init__(self, name="categorical_true_positives", **kwargs):
        super(CategoricalTruePositives, self).__init__(name=name, **kwargs)
        self.true_positives = self.add_weight(name="ctp", initializer="zeros")

    def update_state(self, y_true, y_pred, sample_weight=None):

        #print(f'CatTruePos:: y_true: {y_true} :: y_pred: {y_pred}')

        y_pred = tf.reshape(tf.argmax(y_pred, axis=1), shape=(-1, 1))
        values = tf.cast(y_true, "int32") == tf.cast(y_pred, "int32")
        values = tf.cast(values, "float32")


        #print(f'CatTruePos2:: values: {values} :: y_pred: {y_pred}')

        if sample_weight is not None:
            sample_weight = tf.cast(sample_weight, "float32")
            values = tf.multiply(values, sample_weight)
            #print(f'CatTruePos3:: sample_weight: {sample_weight}')

        self.true_positives.assign_add(tf.reduce_sum(values))

    def result(self):
        return self.true_positives

    def reset_state(self):
        # The state of the metric will be reset at the start of each epoch.
        self.true_positives.assign(0.0)


#Caregorical True Negatives

class CategoricalTrueNegatives(tf.keras.metrics.Metric):

    def __init__(self, name="categorical_true_negatives", **kwargs):
        super(CategoricalTrueNegatives, self).__init__(name=name, **kwargs)

        self.cat_true_negatives = self.add_weight(name="ctn", initializer="zeros")

    def update_state(self, y_true, y_pred, sample_weight=None):


        y_true = K.argmax(y_true, axis=-1)
        y_pred = K.argmax(y_pred, axis=-1)
        y_true = K.flatten(y_true)

        #print(f'CatTrueNeg:: y_true: {y_true} :: y_pred: {y_pred}')

        true_neg = K.sum(K.cast((K.not_equal(y_true, y_pred)), dtype=tf.float32))

        self.cat_true_negatives.assign_add(true_neg)

    def result(self):

        return self.cat_true_negatives
'''


#Caregorical False Negatives
'''
class CategoricalFalseNegatives(tf.keras.metrics.Metric):

    def __init__(self, name="categorical_false_negatives", **kwargs):
        super(CategoricalFalseNegatives, self).__init__(name=name, **kwargs)

        self.cat_false_negatives = self.add_weight(name="cfn", initializer="zeros")

    def update_state(self, y_true, y_pred, sample_weight=None):

        print(f':Update state:')

        y_true = K.argmax(y_true, axis=-1)
        y_pred = K.argmax(y_pred, axis=-1)
        y_true = K.flatten(y_true)

        diff = K.sum(K.cast((K.not_equal(y_true, y_pred)), dtype=tf.float32))
        diff = tf.cast(y_true, "int32") - tf.cast(y_pred, "int32")

        print(f'Diff::{diff}')

        # Correct is 0 
        # FP is -1 
        # FN is 1
        print('CFN Correctly classified: ', np.where(diff == 0)[0])
        print('CFN Incorrectly classified: ', np.where(diff != 0)[0])
        print('CFN False negatives: ', np.where(diff == 1)[0])
        #print(f'CatTrueNeg:: y_true: {y_true} :: y_pred: {y_pred}')

        false_neg = 0

        self.cat_false_negatives.assign_add(false_neg)

    def result(self):

        return self.cat_false_negatives
'''


#Caregorical False Positives
'''
class CategoricalFalsePositives(tf.keras.metrics.Metric):

    def __init__(self, name="categorical_false_positives", **kwargs):
        super(CategoricalFalsePositives, self).__init__(name=name, **kwargs)

        self.cat_false_positives = self.add_weight(name="cfp", initializer="zeros")

    def update_state(self, y_true, y_pred, sample_weight=None):


        y_true = K.argmax(y_true, axis=-1)
        y_pred = K.argmax(y_pred, axis=-1)
        y_true = K.flatten(y_true)

        diff = y_true-y_pred
        #print(f'Diff::{diff}')

        # Correct is 0 
        # FP is -1 
        # FN is 1
        print('CFP Correctly classified: ', np.where(diff == 0)[0])
        print('CFP Incorrectly classified: ', np.where(diff != 0)[0])
        print('CFP False positives: ', np.where(diff == -1)[0])
        
        false_pos = np.where(diff == -1)[0]

        self.cat_false_positives.assign_add(false_pos)

    def result(self):

        return self.cat_false_positives
'''


 
export_model.compile(
    loss=losses.SparseCategoricalCrossentropy(from_logits=False),
    optimizer='adam',
    metrics=['accuracy'],
    
    #metrics=['accuracy',tf.keras.metrics.TruePositives(),tf.keras.metrics.TrueNegatives()],
    #metrics=['accuracy', CategoricalTruePositives()],
    #metrics=[tf.keras.metrics.CategoricalAccuracy(), CategoricalTruePositives(), tf.keras.metrics.FalseNegatives()],

    )

#print("\ntesting raw input to the model...")

#print("\n")
 
#test it with `raw_test_ds`, which yields raw strings
loss, accuracy = export_model.evaluate(raw_test_ds)
#print("\nAccuracy: {:2.2%}".format(accuracy))
#print(f'Loss: {loss}')

#print(f'\nTP: {tp}')
#print(f'\nTN: {tn}')
#print(f'\nFP: {fp}')
#print(f'\nFN: {fn}')

#print(f'\nVAITP raw_test_ds :: {str(raw_test_ds)}')

#print("\n")


#print(f'VAITP Classificator model summary:\n{export_model.summary}')

 

#define function to predict the label with the most score
def get_string_labels(predicted_scores_batch):
  predicted_int_labels = tf.argmax(predicted_scores_batch, axis=1)
  predicted_labels = tf.gather(raw_train_ds.class_names, predicted_int_labels)
  return predicted_labels


predicted_scores = export_model.predict(text_batch)
#print("\n")
predicted_labels = get_string_labels(predicted_scores)

'''
for i, l in raw_train_ds:
    print(f'VAITP :: i :: [i]\nVAITP :: l :: {l.numpy()}')
'''

label_iterator=0
wrong_predictions=0
for input, label in zip(text_batch, predicted_labels):
  #print("\ncode: ", input)

  expected_label_num = label_batch[label_iterator]
  if expected_label_num == 0:
    expected_label = "b'injectable'"
  elif expected_label_num == 1:
    expected_label = "b'noninjectable'"
  else:
    expected_label = "b'vulnerable'"

  predicted_label = label.numpy()

  #print(f'\nexpected label: {expected_label}')
  #print(f'\npredicted label: {predicted_label}')

  if str(predicted_label) != str(expected_label):
      print(f'The following code is {expected_label} but was predicted as {predicted_label}:\n\n\t\t{input}\n\n')
      wrong_predictions += 1

  

  label_iterator += 1


print("\n")
print(f'VAITP total training data-set count :: {label_iterator}')
print(f'VAITP wrong training data-set count :: {wrong_predictions}')
print(f'VAITP correct training data-set count :: {label_iterator-wrong_predictions}')
print("VAITP final model accuracy: {:2.2%}".format(accuracy))
print(f'VAITP final model loss: {loss}')

#Save the model
modelPath = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/exported_ai_models/"
modelPath_Anush = ""
modelexportfilename = modelPath+"vaitp_classificator_model_"+str(int(sys.argv[1]))+"_"+str(int(sys.argv[2]))+"_"+"{:2.2}".format(accuracy)+"_"+strftime("%Y_%m_%d_%H_%M", gmtime())+".tfv"

export_model.save(modelexportfilename)


time_now = time.time()
time_delta = time_now-time_start
print(f'FitModel finished in {timedelta(seconds=time_delta)}')


print("\nVAITP Classificator RNN AI fitted and exported.")