import numpy as np

import typing
from typing import Any, Tuple

import tensorflow as tf

import tensorflow_text as tf_text

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

import pathlib

#path to download vaitp dataset
path_to_zip = tf.keras.utils.get_file(
    'vaitp-dataset-injv-2022.tar.gz', origin='https://netpack.pt/vaitp/vaitp-dataset-injv-2022.tar.gz',
    extract=True)



path_to_file = pathlib.Path(path_to_zip).parent/'injv.txt'


#load the data
def load_data(path):
  text = path.read_text(encoding='utf-8')

  lines = text.splitlines()
  pairs = [line.split('\t') for line in lines]

  inp = [inp for targ, inp in pairs]
  targ = [targ for targ, inp in pairs]

  return targ, inp


inp, targ = load_data(path_to_file)

#print samples
print(f'\nSample injectable data from dataset: {inp[-1]}')
print(f'Sample vulnerable data from dataset: {targ[-1]}\n')

#set buffers sizes
BUFFER_SIZE = len(inp)
BATCH_SIZE = 64

#define the dataset
dataset = tf.data.Dataset.from_tensor_slices((inp, targ)).shuffle(BUFFER_SIZE)
dataset = dataset.batch(BATCH_SIZE)

#print tensor samples
for example_input_batch, example_target_batch in dataset.take(1):
    print(f'\nSample injectable tensor:\n{example_input_batch[:5]}\nSample vulnerable tensor:\n{example_target_batch[:5]}\n')
    break


def tf_lower_and_split_punct(text):
    # Split accecented characters.
    text = tf_text.normalize_utf8(text, 'NFKD')
    #text = tf.strings.lower(text) (don't lower as False != false)
    # Keep space, a to z, and select punctuation.
    #text = tf.strings.regex_replace(text, '[^ a-z.?!,¿]', '') (keep all ponctuation)
    # Add spaces around punctuation.
    text = tf.strings.regex_replace(text, '[.:?!,=\(\)"\']', r' \0 ')
    # Strip whitespace.
    text = tf.strings.strip(text)

    text = tf.strings.join(['[START]', text, '[END]'], separator=' ')
    return text

#print(example_text.numpy())
#print(tf_text.normalize_utf8(example_text, 'NFKD').numpy())

example_text = tf.constant('subprocess.call("uname -n",shell=False)')
print(tf_lower_and_split_punct(example_text).numpy().decode())


max_vocab_size = 5000

input_text_processor = tf.keras.layers.TextVectorization(
    standardize=tf_lower_and_split_punct,
    max_tokens=max_vocab_size)

input_text_processor.adapt(inp)

# Here are the first 10 words from the vocabulary:
print('Vocab extract samples:')
print(input_text_processor.get_vocabulary()[:20])
print()

#convert to tokens
example_tokens = input_text_processor(example_input_batch)
example_tokens[:3, :10]

print("The example_token's tensor is:")
print(example_tokens)

input_vocab = np.array(input_text_processor.get_vocabulary())
tokens = input_vocab[example_tokens[0].numpy()]
print(' '.join(tokens))
