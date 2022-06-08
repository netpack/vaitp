import sys
import os
import collections
import pathlib
import numpy as np
import ast, re

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

from optparse import OptionParser

import astor

time_start = time.time()


#The parser is used to better manipulate the supplied arvgs (just getting to many to handle)
parser = OptionParser()
parser.add_option("-t", "--model_type", action="store", type="string", dest="model_type", help="The type of model to create: 'bow' -> Bag of Words, 'c1d' -> Conv1D, 'lstm' -> LSTM")
parser.add_option("-e", "--epochs", action="store", type="int", dest="epochs", help="The number of epochs that the model sould be fitted (70)")
parser.add_option("-l", "--layer_density", action="store", type="int", dest="layer_density", help="The number of density layers that the model should have (3)")
parser.add_option("-d", "--dropout", action="store", type="float", dest="dropout", help="The dropout value (0.2)")
parser.add_option("-a", "--activation_model_creation", action="store", type="int", dest="activation_model_creation", help="The activation function for the model creation (0 - relu ; 1 - sigmoid ; 2 - tanh ; 3 - softmax ; 4 - softplus ; 5 - selu)")
parser.add_option("-b", "--activation_model_sequencing", action="store", type="int", dest="activation_model_sequencing", help="The activation function for the model sequencing (0 - relu ; 1 - sigmoid ; 2 - tanh ; 3 - softmax ; 4 - softplus ; 5 - selu)")
parser.add_option("-k", "--conv1d_kernel_size", action="store", type="int", dest="conv1d_kernel_size", help="Conv1D Kernel size value: the length of the 1D convolution window (5)")
parser.add_option("-f", "--conv1d_filters", action="store", type="int", dest="conv1d_filters", help="The filters value (128)" )
parser.add_option("-u", "--lstm_units", action="store", type="int", dest="lstm_units", help="The LSTM units value: the size of the LSTM's hidden state (128)")
parser.add_option("-o", "--output_dimensionality", action="store", type="int", dest="output_dimensionality", help="The output dimensionaity (64)" )
parser.add_option("-v", "--vocab_size", action="store", type="int", dest="vocab_size", help="The vocabulary size number: how many words a learner knows (500000)")
parser.add_option("-m", "--max_sequence_length", action="store", type="int", dest="max_sequence_length", help="The maximum length of a sentence (450)" ) 

(options, sys.argv) = parser.parse_args(sys.argv)

#Get params

#Model type
if not options.model_type:
    exit('please specify the model type as -t bow or --model_type bow (see help for all support model types))')


'''Parameters that are common to all models'''
#Model epochs
if int(options.epochs) < 1:
  exit('please add model epochs value as -e 70 or --epochs 70')

#Layer density
if int(options.layer_density) < 1:
  exit('please add layer density value as -l 3 or --layer_density 3')

#Dropout
if float(options.dropout) < 0:
  exit('please add dropout value as -d 0.2 or --dropout 0.2')

#Activation function for the model sequencing (0 - relu ; 1 - sigmoid ; 2 - tanh ; 3 - softmax ; 4 - softplus ; 5 - selu)
if int(options.activation_model_sequencing) < 0:
  exit('please add activation function for the model sequence value as -b 3 or --actionvation_model_sequencing 3')

#Vocabulary size
if int(options.vocab_size) < 0:
  exit('please add vocabulary size value as -v 500000 or --vocab_size 500000')

#max_sequence_length
if int(options.max_sequence_length) < 0:
  exit('please add maximum sequence length value as -m 450 or --max_sequence_length 450')

'''Params that are only for Conv1D and LSTM'''
if options.model_type.upper() == 'C1D' or options.model_type.upper() == 'LSTM':

    #only c1d and lstm have this (not BoW)
    #Activation function for the model creation (0 - relu ; 1 - sigmoid ; 2 - tanh ; 3 - softmax ; 4 - softplus ; 5 - selu)
    if int(options.activation_model_creation) < 0:
        exit('please add activation function for the model creation value as -a 1 or --activation_model_creation 1')

    #output dimensionality (filter units (the dimensionality of the output space) in conv1d and Units(the size of the LSTM's hidden state) in lstm )
    if int(options.output_dimensionality) < 0:
        exit('please add output dimensionality units value as -o 5 or --output_dimensionality 5')


'''Params that are only for Conv1D'''
if options.model_type.upper() == 'C1D':

    #kernel size
    if int(options.conv1d_kernel_size) < 0:
        exit('please add kernel size value as -k 5 or --kernel_size 5')

    #filters
    if int(options.conv1d_filters) < 0:
        exit('please add filters size value as -f 5 or --conv1d_filters 5')



'''Params that are only for LSTM'''
if options.model_type.upper() == 'LSTM':

    #lstm_units
    if int(options.lstm_units) < 0:
        exit('please add lstm units value as -u 7 or --lstm_units 7')






#TODO: Add params:
#Strides
#Padding
if options.model_type.upper() == 'C1D':
    filter_units = int(options.conv1d_filters)
    kernel_size = int(options.conv1d_kernel_size)

activation_function_1="softplus"
activation_function_2="softplus"

#Set activation function for the model creation from param argv[4]
if options.activation_model_creation == 0:
    activation_function_1 = "relu"
elif options.activation_model_creation == 1:
    activation_function_1 = "sigmoid"
elif options.activation_model_creation == 2:
    activation_function_1 = "tanh"
elif options.activation_model_creation == 3:
    activation_function_1 = "softmax"
elif options.activation_model_creation == 4:
    activation_function_1 = "softplus"
elif options.activation_model_creation == 5:
    activation_function_1 = "selu"


#Set activation function for the model sequencing from param argv[5]
if options.activation_model_sequencing == 0:
    activation_function_2 = "relu"
elif options.activation_model_sequencing == 1:
    activation_function_2 = "sigmoid"
elif options.activation_model_sequencing == 2:
    activation_function_2 = "tanh"
elif options.activation_model_sequencing == 3:
    activation_function_2 = "softmax"
elif options.activation_model_sequencing == 4:
    activation_function_2 = "softplus"
elif options.activation_model_sequencing == 5:
    activation_function_2 = "selu"

#Setup logs for tensorboard
log_dir = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/tf_logs/" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
#log_dir = "/mnt/vaitp/VAITP GUI/vaitp/tf_logs/" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
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
train_dir = str(dataset_dir)+'/train'
test_dir = str(dataset_dir)+'/test'

print(f'Training dir path: {train_dir}')
print(f'Testing dir path: {test_dir}')


#print("\nTrain dataset directory listing:")
#print(list(train_dir.iterdir()))

#print sample file
#print("\nSample file content read:")
#sample_file = train_dir/'vulnerable/2.txt'
#with open(sample_file) as f:
#  print(f.read())

#count the number of files in the train dir
train_dir_vuln = train_dir+"/vulnerable"
train_dir_vuln_count = len([n for n in os.listdir(train_dir_vuln) if os.path.isfile(os.path.join(train_dir_vuln, n))])
print(f'File list count in training set: {train_dir_vuln_count} (vulnerable)')

train_dir_noninj = train_dir+"/noninjectable"
train_dir_noninj_count = len([n for n in os.listdir(train_dir_noninj) if os.path.isfile(os.path.join(train_dir_noninj, n))])
print(f'File list count in training set: {train_dir_noninj_count} (noninjectable)')

train_dir_inj = train_dir+"/injectable"
train_dir_inj_count = len([n for n in os.listdir(train_dir_inj) if os.path.isfile(os.path.join(train_dir_inj, n))])
print(f'File list count in training set: {train_dir_inj_count} (injectable)')

train_dir_count = train_dir_inj_count+train_dir_noninj_count+train_dir_vuln_count




#count the number of files in the test dir
test_dir_vuln = test_dir+"/vulnerable"
test_dir_vuln_count = len([n for n in os.listdir(test_dir_vuln) if os.path.isfile(os.path.join(test_dir_vuln, n))])
print(f'File list count in testing set: {test_dir_vuln_count} (vulnerable)')

test_dir_noninj = test_dir+"/noninjectable"
test_dir_noninj_count = len([n for n in os.listdir(test_dir_noninj) if os.path.isfile(os.path.join(test_dir_noninj, n))])
print(f'File list count in testing set: {test_dir_noninj_count} (noninjectable)')

test_dir_inj = test_dir+"/injectable"
test_dir_inj_count = len([n for n in os.listdir(test_dir_inj) if os.path.isfile(os.path.join(test_dir_inj, n))])
print(f'File list count in testing set: {test_dir_inj_count} (injectable)')

test_dir_count = test_dir_vuln_count+test_dir_noninj_count+test_dir_inj_count


#Create a full trainig set for final predictions
raw_train_ds_full = utils.text_dataset_from_directory(
    train_dir,
    batch_size=train_dir_count
    )


#Create trainig set  [should be around 20% of the set]
batch_size = 132#228#64
seed = 4
raw_train_ds = utils.text_dataset_from_directory(
    train_dir,
    batch_size=batch_size,
    validation_split=0.20,
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
    validation_split=0.20,
    subset='validation',
    seed=seed)

#create a test set.
raw_test_ds = utils.text_dataset_from_directory(
    test_dir,
    batch_size=batch_size)


#prepare the datase for training
    #standarization: removes punctuation and html elements to simplify the dataset
    #tokenization: splits strings into tokens
    #vectorization: converts tokens into numbers to be fed into the NN

VOCAB_SIZE = options.vocab_size #50000
MAX_SEQUENCE_LENGTH = options.max_sequence_length #450

if options.model_type.upper() == 'BOW':
    #Binary vectorization builds a "bag full of words" model
    binary_vectorize_layer = TextVectorization(
        max_tokens=VOCAB_SIZE,
        output_mode='binary')

else:
    #int mode: for conv1d and lstm
    int_vectorize_layer = TextVectorization(
        max_tokens=VOCAB_SIZE,
        output_mode='int',
        output_sequence_length=MAX_SEQUENCE_LENGTH)

# Make a text-only dataset (without labels), then call `TextVectorization.adapt`
train_text = raw_train_ds.map(lambda text, labels: text)
if options.model_type.upper() == 'BOW':
    binary_vectorize_layer.adapt(train_text)
else:
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

if options.model_type.upper() == 'BOW':
    #apply textVectorization layers
    binary_train_ds = raw_train_ds.map(binary_vectorize_text)
    binary_val_ds = raw_val_ds.map(binary_vectorize_text)
    binary_test_ds = raw_test_ds.map(binary_vectorize_text)
else:
    int_train_ds = raw_train_ds.map(int_vectorize_text)
    int_val_ds = raw_val_ds.map(int_vectorize_text)
    int_test_ds = raw_test_ds.map(int_vectorize_text)

#prefetch data to buffer
AUTOTUNE = tf.data.AUTOTUNE

def configure_dataset(dataset):
  return dataset.cache().prefetch(buffer_size=AUTOTUNE)

#set the datasets configuration
if options.model_type.upper() == 'BOW':
    binary_train_ds = configure_dataset(binary_train_ds)
    binary_val_ds = configure_dataset(binary_val_ds)
    binary_test_ds = configure_dataset(binary_test_ds)
else:
    int_train_ds = configure_dataset(int_train_ds)
    int_val_ds = configure_dataset(int_val_ds)
    int_test_ds = configure_dataset(int_test_ds)

if options.model_type.upper() == 'BOW':
    #train the model for argv epochs
    binary_model = tf.keras.Sequential([layers.Dropout(float(options.dropout)),layers.Dense(int(options.layer_density))])

    binary_model.compile(
        loss=losses.SparseCategoricalCrossentropy(from_logits=True),
        optimizer='adam',
        metrics=['accuracy'],
        )

    history = binary_model.fit(
        binary_train_ds, 
        validation_data=binary_val_ds, 
        epochs=int(options.epochs),
        callbacks=[tensorboard_callback] 
        )




#use the 'int' vectorized layer to make a Conv1D and LSTM
def create_model(vocab_size, num_labels):
    if options.model_type.upper() == 'C1D':

        model = tf.keras.Sequential([
        layers.Embedding(vocab_size, options.output_dimensionality, mask_zero=True), #input dim, out dim
        layers.Conv1D(filter_units, kernel_size, padding="valid", activation=activation_function_1, strides=1),
        layers.GlobalMaxPooling1D(),
        layers.Dropout(float(options.dropout)),
        layers.Dense(num_labels)
        ])
    elif options.model_type.upper() == 'LSTM':

        model = tf.keras.Sequential([
        layers.Embedding(vocab_size, options.output_dimensionality, mask_zero=True), #input dim, out dim

        #layers.LSTM(options.lstm_units,activation_function_1,dropout=options.dropout),
        
        layers.Bidirectional(tf.keras.layers.LSTM(options.lstm_units, activation=activation_function_1, return_sequences=True)),
        layers.Bidirectional(tf.keras.layers.LSTM(64)),
        #layers.Dense(3, activation=activation_function_1),
        layers.Dense(num_labels),


        #layers.ConvLSTM1D(64, return_sequences=True),
        
        ])



    return model

# `vocab_size` is `VOCAB_SIZE + 1` since `0` is used additionally for padding.

if options.model_type.upper() != 'BOW':
    int_model = create_model(vocab_size=VOCAB_SIZE + 1, num_labels=3)
    int_model.compile(
        loss=losses.SparseCategoricalCrossentropy(from_logits=True),
        optimizer='adam',
        metrics=['accuracy'])
    history = int_model.fit(int_train_ds, validation_data=int_val_ds, epochs=int(options.epochs), callbacks=[tensorboard_callback])


'''
#compare the two models:
print("\nlinear model on binary vectorized data:")
print(binary_model.summary())

#sumarise ConvNet model:
print("\nconvNet model on int vectorized data:")
print(int_model.summary())
'''

#evaluate models accuracy:

if options.model_type.upper() == 'BOW':
    binary_loss, binary_accuracy = binary_model.evaluate(binary_test_ds)
    print("\nBag of Words model accuracy: {:2.2%}".format(binary_accuracy))
else:
    int_loss, int_accuracy = int_model.evaluate(int_test_ds)
    if options.model_type.upper() == 'C1D':
        print("\nConv1D model accuracy: {:2.2%}".format(int_accuracy))
    else:
        print("\LSTM model accuracy: {:2.2%}".format(int_accuracy))



#print("\n\nmodel trained. exporting the model...\n\n")

#export the model
if options.model_type.upper() == 'BOW':
    export_model = tf.keras.Sequential(
        [binary_vectorize_layer, binary_model,
        layers.Activation(activation_function_2)])
else:
    export_model = tf.keras.Sequential(
        [int_vectorize_layer, int_model,
        layers.Activation(activation_function_2)])

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

  def ast_to_code(ast_string):
   return ast.unparse(eval(re.sub('\w+(?=\()', lambda x:f'ast.{x.group()}', ast_string)))


  if str(predicted_label) != str(expected_label):
      print(f'\nThe following code is {expected_label} but was predicted as {predicted_label}:\n\n\t\t{input}\n\n')
      #source = astor.to_source(ast.parse(str(input.numpy())[2:][:-1].replace("\\n","").replace("\\t","")))

      #print(f'Original Python code: {ast.dump(ast.parse(source))}')
      wrong_predictions += 1

  

  label_iterator += 1


print("\n")
print(f'VAITP total training data-set count :: {train_dir_count}')
print(f'VAITP total testing data-set count :: {test_dir_count}')
print(f'VAITP wrong testing data-set count :: {wrong_predictions}')
print(f'VAITP correct testing data-set count :: {test_dir_count-wrong_predictions}')
print("VAITP final model accuracy: {:2.2%}".format(accuracy))
print(f'VAITP final model loss: {loss}')

#Save the model
modelPath = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/exported_ai_models/"
#modelPath = "/mnt/vaitp/VAITP GUI/vaitp/exported_ai_models/"
modelexportfilename = modelPath+"vaitp_classificator_model_"+"{:2.2}".format(accuracy)+"_"+str(options.model_type.upper())+"_"+str(int(options.epochs))+"_"+str(int(options.layer_density))+"_"+strftime("%Y_%m_%d_%H_%M", gmtime())+".tfv"

export_model.save(modelexportfilename)


time_now = time.time()
time_delta = time_now-time_start
print(f'FitModel finished in {timedelta(seconds=time_delta)}')


print("\nVAITP Classificator RNN AI fitted and exported.")