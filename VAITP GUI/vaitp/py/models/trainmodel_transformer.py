import logging
import time

import numpy as np
import matplotlib.pyplot as plt

import tensorflow_datasets as tfds
import tensorflow as tf

# Import tf_text to load the ops used by the tokenizer saved model
import tensorflow_text  # pylint: disable=unused-import


#Import VAITP custom dataset
import datasets.vaitp_dataset.vaitp_dataset


#no warnings
logging.getLogger('tensorflow').setLevel(logging.ERROR)  # suppress warnings


ds = tfds.load('vaitp_dataset')

print('VATIP dataset loaded.')
