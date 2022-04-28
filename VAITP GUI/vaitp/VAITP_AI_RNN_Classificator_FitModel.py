import sys
import collections
import pathlib
import numpy as np

import tensorflow_datasets as tfds
import tensorflow as tf

from tensorflow.keras import layers
from tensorflow.keras import losses
from tensorflow.keras import utils
from tensorflow.keras.layers import TextVectorization

import tensorflow_datasets as tfds
import tensorflow_text as tf_text

tfds.disable_progress_bar()

import matplotlib.pyplot as plt

from time import gmtime, strftime

if int(sys.argv[1]) < 1:
  exit('please input training epochs value as argv1 [30 10 3]')

if int(sys.argv[2]) < 1:
  exit('please input testing epochs value as argv2 [30 10 3]')

if int(sys.argv[3]) < 1:
  exit('please input RNN Density value as argv3 [30 10 3]')

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


#Create validation set  [should be around 20% of the set]
batch_size = 10
seed = 4
raw_train_ds = utils.text_dataset_from_directory(
    train_dir,
    batch_size=batch_size,
    validation_split=0.2,
    subset='training',
    seed=seed)

#show what the lables correspond to
#for i, label in enumerate(raw_train_ds.class_names):
#  print("Label", i, "corresponds to", label)


#iterate randomly on the data to feel it better
#for text_batch, label_batch in raw_train_ds.take(1):
#  for i in range(10):
#    print("code: ", text_batch.numpy()[i])
#    print("Label:", label_batch.numpy()[i])

#create a validation set.
raw_val_ds = utils.text_dataset_from_directory(
    train_dir,
    batch_size=batch_size,
    validation_split=0.2,
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
text_batch, label_batch = next(iter(raw_train_ds))
first_code, first_label = text_batch[0], label_batch[0]
#print("\ncode: ", first_code)
#print("\nlabel: ", first_label)

#print binary and int versions
#print("'binary' vectorized code:",
#      binary_vectorize_text(first_code, first_label)[0])
#print("'int' vectorized code:",
#      int_vectorize_text(first_code, first_label)[0])


#apply textVectorization layers
binary_train_ds = raw_train_ds.map(binary_vectorize_text)
binary_val_ds = raw_val_ds.map(binary_vectorize_text)
binary_test_ds = raw_test_ds.map(binary_vectorize_text)

int_train_ds = raw_train_ds.map(int_vectorize_text)
int_val_ds = raw_val_ds.map(int_vectorize_text)
int_test_ds = raw_test_ds.map(int_vectorize_text)

#prefetch data to buffer
AUTOTUNE = tf.data.AUTOTUNE

def configure_dataset(dataset):
  return dataset.cache().prefetch(buffer_size=AUTOTUNE)

binary_train_ds = configure_dataset(binary_train_ds)
binary_val_ds = configure_dataset(binary_val_ds)
binary_test_ds = configure_dataset(binary_test_ds)

int_train_ds = configure_dataset(int_train_ds)
int_val_ds = configure_dataset(int_val_ds)
int_test_ds = configure_dataset(int_test_ds)


#train the model for 10 epochs
binary_model = tf.keras.Sequential([layers.Dense(int(sys.argv[3]))])

binary_model.compile(
    loss=losses.SparseCategoricalCrossentropy(from_logits=True),
    optimizer='adam',
    metrics=['accuracy'])

history = binary_model.fit(
    binary_train_ds, validation_data=binary_val_ds, epochs=int(sys.argv[1]))


#use the 'int' vectorized layer to make a 1D convolutional neural network (1D are good for text)
def create_model(vocab_size, num_labels):
  model = tf.keras.Sequential([
      layers.Embedding(vocab_size, 64, mask_zero=True),
      layers.Conv1D(64, 5, padding="valid", activation="relu", strides=2),
      #layers.ConvLSTM1D(64, return_sequences=True),
      layers.GlobalMaxPooling1D(),
      layers.Dropout(0.2),
      #layers.Bidirectional(tf.keras.layers.LSTM(64,  return_sequences=True)),
      #layers.Bidirectional(tf.keras.layers.LSTM(32)),
      #layers.Dense(64, activation='relu'),
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
history = int_model.fit(int_train_ds, validation_data=int_val_ds, epochs=int(sys.argv[2]))


#compare the two models:
#print("\nlinear model on binary vectorized data:")
#print(binary_model.summary())

#sumarise ConvNet model:
#print("\nconvNet model on int vectorized data:")
#print(int_model.summary())

#evaluate models accuracy:
binary_loss, binary_accuracy = binary_model.evaluate(binary_test_ds)
int_loss, int_accuracy = int_model.evaluate(int_test_ds)

#print("\nbinary model accuracy: {:2.2%}".format(binary_accuracy))
#print("\nint model accuracy: {:2.2%}".format(int_accuracy))

#print("\n\nmodel trained. exporting the model...\n\n")

#export the model
export_model = tf.keras.Sequential(
    [binary_vectorize_layer, binary_model,
     layers.Activation('sigmoid')])

#print("\n")
 
export_model.compile(
    loss=losses.SparseCategoricalCrossentropy(from_logits=False),
    optimizer='adam',
    metrics=['accuracy'])

#print("\ntesting raw input to the model...")

#print("\n")
 
#test it with `raw_test_ds`, which yields raw strings
loss, accuracy = export_model.evaluate(raw_test_ds)
print("\nAccuracy: {:2.2%}".format(binary_accuracy))

#print("\n")
 

#define function to predict the label with the most score
def get_string_labels(predicted_scores_batch):
  predicted_int_labels = tf.argmax(predicted_scores_batch, axis=1)
  predicted_labels = tf.gather(raw_train_ds.class_names, predicted_int_labels)
  return predicted_labels


#print("\n")
 
#run on new data
'''
inputs = [
    "comando = 'ffmpeg -i {ficheiro} saida.mkv'.format(ficheiro=filename)' subprocess.call(comando,shell=False)",  # 'injectable'
    "cmds = 'ffmpeg -i {s} out.mkv'.format(s=file)' subprocess.call(cmds,shell=True)",  # 'vulnerable'
    "cmds = 'ffmpeg -i {s} out.mkv'.format(s=quote(file))' subprocess.call(cmds,shell=True)",  # 'injectable'
    "import sys     def somefunction(in):   etree.XMLParser(resolve_entities=False)", # 'injectable'
    "import sys     def somefunction(in):   etree.XMLParser(resolve_entities=True)", # 'vulnerable'
    "import sys     def somefunction(in):   etree.XMLParser()", # 'vulnerable'
    "import sys     eval(quote(sys.argv[1]))", # 'injectable'
    "import sys     eval(sys.argv[1])", # 'vulnerable'
    "import sys     exec(quote(sys.argv[1]))", # 'injectable'
    "import sys     exec(var)", # 'vulnerable'
]'''

'''
inputs = [
"quoted_var = quote(sys.argv[1])\
\
# vaitp random comment\
try:\
    exec(os.path.join(local_dir, os.path.basename(quoted_var)))\
except:\
    print('string com mensagem de erro')\
",
]'''
'''
inputs = [
"\
#here we have an important comment\
def vaitpNewTestCase():\
  if sys.argv[1]:\
    this_var = urllib.parse.quote(sys.argv[1])\
    print('important vaitp msg')\
  else:\
    print('required parameter not found') #something here\
",
]
'''
#3 injectable
#3 vulnerable
#3 noninjectable
expected_predictions = ["b'injectable'","b'injectable'","b'injectable'",\
"b'vulnerable'","b'vulnerable'","b'vulnerable'",\
"b'noninjectable'","b'noninjectable'","b'noninjectable'",\
]

#print(f'expected_predictions[8] is: {expected_predictions[8]}')

#9 new code inputs; 3 injerable + 3 vulnerable + 3 noninjetable
'''
inputs = [
"\
this_var = urllib.parse.quote(sys.argv[1])\
","\
exec(quote(sys.argv[2]))\
","\
runVAITPFunc(quote(input(\"Please input x value:\")))\
",
"\
load_data = sys.argv[1]\
","\
nome = input_raw(\"Name:\")\
","\
somevname = sys.argv[1]\
","\
#thisisacomment\
","\
\"\"\" this is a different type \n of comment that can be written in multiple lines \n also considered as not injectable\"\"\"\
","\
import BeautifulSoup as bs\
",
]
'''

inputs = [
"\
Module(\
    body=[\
        Assign(\
            targets=[\
                Name(id='this_var', ctx=Store())],\
            value=Call(\
                func=Attribute(\
                    value=Attribute(\
                        value=Name(id='urllib', ctx=Load()),\
                        attr='parse',\
                        ctx=Load()),\
                    attr='quote',\
                    ctx=Load()),\
                args=[\
                    Subscript(\
                        value=Attribute(\
                            value=Name(id='sys', ctx=Load()),\
                            attr='argv',\
                            ctx=Load()),\
                        slice=Constant(value=1),\
                        ctx=Load())],\
                keywords=[]))],\
    type_ignores=[])\
","\
  Module(\
    body=[\
        Expr(\
            value=Call(\
                func=Name(id='exec', ctx=Load()),\
                args=[\
                    Call(\
                        func=Name(id='quote', ctx=Load()),\
                        args=[\
                            Subscript(\
                                value=Attribute(\
                                    value=Name(id='sys', ctx=Load()),\
                                    attr='argv',\
                                    ctx=Load()),\
                                slice=Constant(value=2),\
                                ctx=Load())],\
                        keywords=[])],\
                keywords=[]))],\
    type_ignores=[])\
  ","\
  Module(\
    body=[\
        Expr(\
            value=Call(\
                func=Name(id='runVAITPFunc', ctx=Load()),\
                args=[\
                    Call(\
                        func=Name(id='quote', ctx=Load()),\
                        args=[\
                            Call(\
                                func=Name(id='input', ctx=Load()),\
                                args=[\
                                    Constant(value='Please input x value:')],\
                                keywords=[])],\
                        keywords=[])],\
                keywords=[]))],\
    type_ignores=[])\
  ", "\
  Module(\
    body=[\
        Assign(\
            targets=[\
                Name(id='load_data', ctx=Store())],\
            value=Subscript(\
                value=Attribute(\
                    value=Name(id='sys', ctx=Load()),\
                    attr='argv',\
                    ctx=Load()),\
                slice=Constant(value=1),\
                ctx=Load()))],\
    type_ignores=[])\
  ", "\
    Module(\
    body=[\
        Assign(\
            targets=[\
                Name(id='nome', ctx=Store())],\
            value=Call(\
                func=Name(id='input_raw', ctx=Load()),\
                args=[\
                    Constant(value='Name:')],\
                keywords=[]))],\
    type_ignores=[])\
    ", "\
Module(\
    body=[\
        Assign(\
            targets=[\
                Name(id='somevname', ctx=Store())],\
            value=Subscript(\
                value=Attribute(\
                    value=Name(id='sys', ctx=Load()),\
                    attr='argv',\
                    ctx=Load()),\
                slice=Constant(value=1),\
                ctx=Load()))],\
    type_ignores=[])\
      " , "\
        Module(body=[], type_ignores=[])\
        ","\
          Module(\
    body=[\
        Expr(\
            value=Constant(value=' this is a different type \n of comment that can be written in multiple lines \n also considered as not injectable'))],\
    type_ignores=[])\
          ","\
            Module(\
    body=[\
        Import(\
            names=[\
                alias(name='BeautifulSoup', asname='bs')])],\
    type_ignores=[])\
            ",
]

predicted_scores = export_model.predict(inputs)
#print("\n")
predicted_labels = get_string_labels(predicted_scores)
#print("\n")
n=0 # num of iterations and vector index

'''
tp=0 # true positives (an expected prediction is the same as the actual prediction)
fp=0 # false positives (an expected injectable was miss classified in the prediction as vulnerable or noninjectable)
tn=0 # true negatives (an expected vulnerable was miss classified in the prediction as injectable or noninjectable)
fn=0 # false negatives (an expected noninjerable was miss classified in the prediction as injectable or vulnerable)'''

cp=0 # correct preditions
ip=0 # incorrect preditions
for input, label in zip(inputs, predicted_labels):
  print("\ncode: ", input)
  print("\npredicted label: ", label.numpy())

  '''
  #print(f'expected_predictions[{n}]: {expected_predictions[n]}')
  if expected_predictions[n] == str(label.numpy()): #injectable -> injectable | vulnerable -> vulnerable | noninjectable -> noninjetable
    #print("Considered correct adding to TP")
    tp+=1
  elif expected_predictions[n] == "b'injectable'": #injectable -> vulnerable or noninjectable
      #print("Considered incorrect adding to FP")
      fp+=1
  elif expected_predictions[n] == "b'vulnerable'": #vulnerable -> injectable or noninjectable
      #print("Considered incorrect adding to TN")
      tn+=1  
  elif expected_predictions[n] == "b'noninjectable'": #noninjectable -> injectable or vulnerab
      #print("Considered incorrect adding to FN")
      fn+=1'''

  if expected_predictions[n] == str(label.numpy()): #injectable -> injectable | vulnerable -> vulnerable | noninjectable -> noninjetable
    cp+=1
  else:
    ip+=1    
  n+=1


print(f'Correct predictions: {cp}')
print(f'Incorrect predictions: {ip}')

'''
print(f'True Positives: {tp}')
print(f'False Positives: {fp}')

print(f'True Negatives: {tp}')
print(f'False Negatives: {fp}')
'''


modelPath = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/exported_ai_models/"
modelPath_Anush = ""
modelexportfilename = modelPath+"vaitp_classificator_model_"+str(int(sys.argv[1]))+"_"+str(int(sys.argv[2]))+"_"+str(int(sys.argv[3]))+"_"+"{:2.2}".format(binary_accuracy)+"_"+strftime("%Y_%m_%d_%H_%M", gmtime())+".tfv"

#Save the model
export_model.save(modelexportfilename)



print("\n")
print("\nVAITP Classificator RNN AI fitted and exported.")