import sys
#from tensorflow import keras
import tensorflow as tf
import ast
#import numpy as np
import pathlib
from optparse import OptionParser


#parameters parsing
parser = OptionParser()
parser.add_option("-i", "--input_file", action="store", type="string", dest="input_file", help="Set the input Python file to be scanned")
parser.add_option("-o", "--optimize_granularity", action="store_true", dest="optimize_granularity", help="Try to optimize granulariy of inputs predicted as 'injectable'")
parser.add_option("-m", "--use-model", action="store", type="string", dest="use_model", help="Set the model to use")

(options, sys.argv) = parser.parse_args(sys.argv)


#define function to predict the label with the most score
def get_string_labels(predicted_scores_batch):
  predicted_int_labels = tf.argmax(predicted_scores_batch, axis=1)
  predicted_labels = tf.gather(raw_train_ds.class_names, predicted_int_labels)
  return predicted_labels



#print("Starting VAITP AI RNN Classicator RunModel...")


#Vars
path_to_exported_models = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/exported_ai_models/"
#model_name = "vaitp_classificator_model_8000_10000_1370_0.99_2022_04_25_10_44.tfv"
if not options.use_model:
  model_name = "vaitp_classificator_model_0.86_BOW_80_5_2022_05_21_11_38.tfv"
else:
  model_name = options.use_model

input_newcode = "../vaitp/VAITP_AI_RNN_Classificator_newInput.vaitp"
pyfile = "vaitpscan.py"

#force -i infile.py
if options.input_file:
  pyfile = options.input_file
else:
  exit("Please add an input file. (-i dir/file.py)")

pyfile_fp = open(pyfile,'r')

#print(f'py:: {pyfile_fp.read()}')
source = pyfile_fp.read()
pyfile_ast_parsed = ast.parse(source, mode='exec')
pyfile_ast = ast.dump(pyfile_ast_parsed)



#Load the model
if not options.use_model:
  model_p = path_to_exported_models+model_name
else:
  model_p = model_name #with -m the full path is expected

model = tf.keras.models.load_model(model_p)

#print(f'Model Loaded: {model_name}')

#print(f'Model Summary: {model.summary()}')



#Get new input
#with open(input_newcode,'r') as fin:
#    lines = fin.readlines()
#print('ffff')

final_input_string = []
final_lines = ""


for line in pyfile_ast: #lines:
    #final_input_string.append(line)
    final_lines += line

final_input_string.append(final_lines)

#print(f'New code vector: {final_input_string}')


dataset_dir = pathlib.Path("../vaitp/vaitp_dataset_ast")
train_dir = dataset_dir/'train'
batch_size = 10
seed = 4
raw_train_ds = tf.keras.utils.text_dataset_from_directory(
    train_dir,
    batch_size=batch_size,
    validation_split=0.2,
    subset='training',
    seed=seed)


predicted_scores = model.predict(final_input_string)
predicted_labels = get_string_labels(predicted_scores)

for input, label in zip(final_input_string, predicted_labels):
  #print("\ncode: ", input)
  predicted_label = label.numpy()
  print("predicted label: ", predicted_label)
  if options.optimize_granularity:
    print(f'Detected an injectable code. Trying to optimize granularity...')
    for node in ast.walk(pyfile_ast_parsed):
      line = ast.dump(node)
      #print(f'AST Node Line: {line}')
      
      line_ps = model.predict([line])
      line_pl = get_string_labels(line_ps)
      #line_in, line_la = zip(line,line_pl)
      #line_prediction = line_la.numpy()
      #print(f'Prediction: {line_pl.numpy()} Line: {line}')
      line_prediction = line_pl.numpy()
      if str(line_prediction) == "[b'injectable']":
        pycode = str(ast.get_source_segment(source,node))
        n = pycode.count('\n')
        if n == 0 and pycode != 'None':
          print(f'[{n}] Injectable AST node python code: {pycode}')
      

