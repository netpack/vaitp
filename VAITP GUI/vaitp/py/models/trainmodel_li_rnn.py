import collections
import helper
import numpy as np
import project_tests as tests
from keras.preprocessing.text import Tokenizer
from keras.preprocessing.sequence import pad_sequences
from keras.models import Model
from keras.layers import GRU, Input, Dense, TimeDistributed, Activation, RepeatVector, Bidirectional
from keras.layers.embeddings import Embedding
from tensorflow.keras.optimizers import Adam
from keras.losses import sparse_categorical_crossentropy
from keras.models import Sequential

#tokenizer
def tokenize(x):
    x_tk = Tokenizer(char_level = False)
    x_tk.fit_on_texts(x)
    return x_tk.texts_to_sequences(x), x_tk

#Add padding
def pad(x, length=None):
    if length is None:
        length = max([len(sentence) for sentence in x])
    return pad_sequences(x, maxlen = length, padding = 'post')    

#preprocess tokenized data
def preprocess(x, y):
    preprocess_x, x_tk = tokenize(x)
    preprocess_y, y_tk = tokenize(y)
    preprocess_x = pad(preprocess_x)
    preprocess_y = pad(preprocess_y) #Keras's sparse_categorical_crossentropy function labels have to be in 3 dimensions
    preprocess_y = preprocess_y.reshape(*preprocess_y.shape, 1)
    return preprocess_x, preprocess_y, x_tk, y_tk


#convert logits back to code
def logits_to_text(logits, tokenizer):
    index_to_words = {id: word for word, id in tokenizer.word_index.items()}
    index_to_words[0] = '<PAD>'
    return ' '.join([index_to_words[prediction] for prediction in np.argmax(logits, 1)])


#Create simple rnn model for vulnerability injection
def simple_model(input_shape, output_sequence_length, injectable_vocab_size, vulnerable_vocab_size):
    learning_rate = 1e-3
    input_seq = Input(input_shape[1:])
    rnn = GRU(64, return_sequences = True)(input_seq)
    logits = TimeDistributed(Dense(vulnerable_vocab_size))(rnn)
    model = Model(input_seq, Activation('softmax')(logits))
    model.compile(loss = sparse_categorical_crossentropy, 
                 optimizer = Adam(learning_rate), 
                 metrics = ['accuracy'])
    
    return model


def embed_model(input_shape, output_sequence_length, injectable_vocab_size, vulnerable_vocab_size):
    """
    Build and train a RNN model using word embedding on x and y
    :param input_shape: Tuple of input shape
    :param output_sequence_length: Length of output sequence
    :param injectable_vocab_size: Number of unique injectable words in the dataset
    :param vulnerable_vocab_size: Number of unique vulnerable words in the dataset
    :return: Keras model built, but not trained
    """
    learning_rate = 1e-3
    rnn = GRU(64, return_sequences=True, activation="tanh")
    
    embedding = Embedding(vulnerable_vocab_size, 64, input_length=input_shape[1]) 
    logits = TimeDistributed(Dense(vulnerable_vocab_size, activation="softmax"))
    
    model = Sequential()
    model.add(embedding)
    model.add(rnn)
    model.add(logits)
    model.compile(loss=sparse_categorical_crossentropy,
                  optimizer=Adam(learning_rate),
                  metrics=['accuracy'])
    
    return model




injectable_sentences = helper.load_data('data/src-train.txt')
vulnerable_sentences = helper.load_data('data/tgt-train.txt')


print('\nVAITP [AI_LI_RNN] :: Dataset Loaded')


print('\nSamples from dataset:')
for sample_i in range(2):
    print('vocab_injectable Line {}:  {}'.format(sample_i + 1, injectable_sentences[sample_i]))
    print('vocab_vulnerable Line {}:  {}'.format(sample_i + 1, vulnerable_sentences[sample_i]))


print('\nCounting statistics from dataset:')
injectable_words_counter = collections.Counter([word for sentence in injectable_sentences for word in sentence.split()])
vulnerable_words_counter = collections.Counter([word for sentence in vulnerable_sentences for word in sentence.split()])

print('{} injectable words.'.format(len([word for sentence in injectable_sentences for word in sentence.split()])))
print('{} unique injectable words.'.format(len(injectable_words_counter)))
print()
print('10 Most common words in the injectable dataset:')
print('"' + '" "'.join(list(zip(*injectable_words_counter.most_common(10)))[0]) + '"')
print()
print('{} vulnerable words.'.format(len([word for sentence in vulnerable_sentences for word in sentence.split()])))
print('{} unique vulnerable words.'.format(len(vulnerable_words_counter)))
print('10 Most common words in the vulnerable dataset:')
print('"' + '" "'.join(list(zip(*vulnerable_words_counter.most_common(10)))[0]) + '"')


print('\nTokenizing sample data...')
text_sentences = [
    'subprocess.call(cmd, shell=False)',
    'subprocess.run(cmd, shell=False)'
    ]
text_tokenized, text_tokenizer = tokenize(text_sentences)
print(text_tokenizer.word_index)
print()
for sample_i, (sent, token_sent) in enumerate(zip(text_sentences, text_tokenized)):
    print('Sequence {} in x'.format(sample_i + 1))
    print('  Input:  {}'.format(sent))
    print('  Output: {}'.format(token_sent))


print('\nPadding sample data...')
test_pad = pad(text_tokenized)
for sample_i, (token_sent, pad_sent) in enumerate(zip(text_tokenized, test_pad)):
    print('Sequence {} in x'.format(sample_i + 1))
    print('  Input:  {}'.format(np.array(token_sent)))
    print('  Output: {}'.format(pad_sent))


print('\nPreprocessing data...')   
preproc_injectable_sentences, preproc_vulnerable_sentences, injectable_tokenizer, vulnerable_tokenizer =\
    preprocess(injectable_sentences, vulnerable_sentences)
    
max_injectable_sequence_length = preproc_injectable_sentences.shape[1]
max_vulnerable_sequence_length = preproc_vulnerable_sentences.shape[1]
injectable_vocab_size = len(injectable_tokenizer.word_index)
vulnerable_vocab_size = len(vulnerable_tokenizer.word_index)
print('Data Preprocessed')
print("Max injectable sentence length:", max_injectable_sequence_length)
print("Max vulnerable sentence length:", max_vulnerable_sequence_length)
print("injectable vocabulary size:", injectable_vocab_size)
print("vulnerable vocabulary size:", vulnerable_vocab_size)

#temporary shapes
tmp_x = pad(preproc_injectable_sentences, max_vulnerable_sequence_length)
tmp_x = tmp_x.reshape((-1, preproc_vulnerable_sentences.shape[-2], 1))

embeded_model = embed_model(
    tmp_x.shape,
    max_vulnerable_sequence_length,
    injectable_vocab_size,
    vulnerable_vocab_size)

embeded_model.fit(tmp_x, preproc_vulnerable_sentences, batch_size=2, epochs=10, validation_split=0.2)


# TODO: Print prediction(s)
print(logits_to_text(embeded_model.predict(tmp_x[:1])[0], vulnerable_tokenizer))