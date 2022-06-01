import sys
#from tensorflow import keras
import tensorflow as tf
#import tensorflow_datasets as tfds
#from tensorflow.keras import layers
#from tensorflow.keras import losses
#from tensorflow.keras import utils
#from tensorflow.keras.layers import TextVectorization
#import tensorflow_datasets as tfds
#import tensorflow_text as tf_text
#import ast
#import numpy as np
#import pathlib
from optparse import OptionParser


#parameters parsing
parser = OptionParser()
parser.add_option("-i", "--input_file", action="store", type="string", dest="input_string", help="Set the input Python string to be translated")

(options, sys.argv) = parser.parse_args(sys.argv)

#Vars
path_to_exported_models = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/exported_ai_models/"
model_name = "vaitp_s2s_model_70_2022_05_31_17_02.tfv"


#Remove extra spaces that were added around punctuation (for output)
def tf_rebuild_string(text):
  return text.replace(" . ",".").replace(" : ",":").replace(" ? ","?").replace(" ! ","!").replace(" , ",",").replace(" = ","=").replace(" \\ ","\\").replace(" ( ","(").replace(" / ","/").replace(" ) ",")").replace(" \" ","\"").replace(" ' ","'").replace(" - ","-").replace(" .",".").replace(" :",":").replace(" ?","?").replace(" !","!").replace(" ,",",").replace(" =","=").replace(" \\","\\").replace(" (","(").replace(" /","/").replace(" )",")").replace(" \"","\"").replace(" '","'").replace(" -","-")


#Load the model
model_p = path_to_exported_models+model_name
reloaded = tf.saved_model.load(model_p)

#set the string passed as argv as a tf constant vector
input_text = tf.constant([
    str(options.input_string)
])

result = reloaded.tf_translate(
    input_text = input_text)

print("Result:")
print( tf_rebuild_string(result['text'][0].numpy().decode()) )
print("")