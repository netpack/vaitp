import sys, ast, pickle, keras, tensorflow as tf
from optparse import OptionParser

print("Starting VAITP AI RNN RunModel Script")
print("TensorFlow version:", tf.__version__)
print("Keras version:", keras.__version__)

# Keep it quiet...
# sys.stderr = open(os.devnull, 'w')
# tf.get_logger().setLevel('ERROR')

# Parameters parsing
parser = OptionParser()
parser.add_option("-i", "--input_file", action="store", type="string", dest="input_file", help="Set the input Python file to be scanned")
parser.add_option("-o", "--optimize_granularity", action="store_true", dest="optimize_granularity", help="Try to optimize granularity of inputs predicted as 'injectable'")
parser.add_option("-m", "--use-model", action="store", type="string", dest="use_model", help="Set the model to use")

(options, sys.argv) = parser.parse_args(sys.argv)

# Define function to predict the label with the most score
def get_string_labels(predicted_scores_batch):
    predicted_int_labels = tf.argmax(predicted_scores_batch, axis=1)
    class_names = ["injectable", "noninjectable"]
    return [class_names[idx] for idx in predicted_int_labels.numpy()]


# Vars
path_to_exported_models = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/exported_ai_models/"
if not options.use_model:
    model_name = "vaitp_classificator_model_0.74_BOW_90_7_2024_12_13_17_29.keras"
else:
    model_name = options.use_model

# Force -i infile.py
if options.input_file:
    pyfile = options.input_file
else:
    exit("Please add an input file. (-i dir/file.py)")

try:
    with open(pyfile, 'r') as pyfile_fp:
      source = pyfile_fp.read()
    pyfile_ast_parsed = ast.parse(source, mode='exec')
except Exception as e:
  exit(f"Error when parsing the input file. {e}")
pyfile_ast = ast.dump(pyfile_ast_parsed, indent=4)
# Load the model
if not options.use_model:
    model_p = path_to_exported_models + model_name
else:
    model_p = model_name  # Full path is expected

try:
    model = tf.keras.models.load_model(model_p)
except Exception as e:
    exit(f"Error when loading the model from {model_p}: {e}")

# Load tokenizer (assuming it is saved as <model_path>_tokenizer.pickle)
tokenizer_path = model_p.replace(".keras", "_tokenizer.pickle")
try:
    with open(tokenizer_path, 'rb') as handle:
        tokenizer = pickle.load(handle)
except FileNotFoundError:
    exit(f"Error: Tokenizer file not found at {tokenizer_path}")
except Exception as e:
    exit(f"Error loading tokenizer: {e}")


#Get new input
final_input_string = str(pyfile_ast)

# Preprocess Input
# No additional preprocessing needed
processed_input = final_input_string

# Make predictions
predicted_scores = model.predict(tf.constant([processed_input]), verbose=0)
predicted_labels = get_string_labels(predicted_scores)

for input_str, label in zip([final_input_string], predicted_labels): # list of strings, list of predicted labels
    predicted_label = label
    print("predicted label: ", predicted_label)

    # Output probable injection locations
    if options.optimize_granularity and str(predicted_label) == "injectable":
        print("Detected an injectable code. Trying to optimize granularity...")
        for node in ast.walk(pyfile_ast_parsed):
            try:
                #try to predict the label for the node itself
                #preprocess data
                node_line = ast.dump(node)
                 # No additional preprocessing needed
                node_input = node_line

                node_scores = model.predict(tf.constant([node_input]), verbose=0)
                node_labels = get_string_labels(node_scores)

                if str(node_labels[0]) == "injectable":
                    pycode = str(ast.get_source_segment(source, node))
                    if pycode != 'None':
                      n = pycode.count('\n')
                      print(f'[{n}] Injectable AST node python code: {pycode}')
            except Exception as e:
                #print(f'VAITP Exception handler got: {e}') #can be noisy
                pass