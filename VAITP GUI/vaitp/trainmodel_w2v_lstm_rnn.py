from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from gensim.models import Word2Vec
from gensim.models import TranslationMatrix
import os
import nltk
import sys
import ast
import glob
import gensim
nltk.download('punkt')

class CustomNodeVisitor(ast.NodeVisitor):
    def visit(self, node):
        print(node.__class__.__name__)
        return ast.NodeVisitor.visit(self, node)


print('VAITP :: Train AI model [W2V LSTM RNN]')

#dataset paths
dir_vulnerable = "vaitp_dataset/train/vulnerable"
dir_injectable = "vaitp_dataset/train/injectable"

#vulnerable AST vector
vvector = ""
#injectable AST vector
ivector = ""

print()

#vectorize vulnerable dataset
print('Vectorizing vulnerable dataset...')
for astfile in glob.iglob(f'{dir_vulnerable}/*.txt'):
    print(f'Vectorizing AST: {astfile}')
    fin = open(astfile, "r")
    #vvector.append(fin.read())
    astcode = fin.read()
    tree = ast.parse(astcode, mode='exec')
    print(f'The ast dump from vulnerable tree is: {ast.dump(tree)}')
    #CustomNodeVisitor().visit(tree)
    for node in ast.walk(tree):
        #print(f'AST VV NODE :: {ast.dump(node)}')
        #vvector.append(ast.dump(node))
        try:
            param = node.keywords[0].arg        
            if param:
                vvector += param + " "
            val = str(node.keywords[0].value.value)
            if val:
                vvector += val + " "
        except:
            pass

print('\nvvector contains:')
print(vvector)
print()

#vectorize injectable dataset
print('Vectorizing injectable dataset...')
for astfile in glob.iglob(f'{dir_injectable}/*.txt'):
    print(f'Vectorizing AST: {astfile}')
    fin = open(astfile, "r")
    #ivector.append(fin.read())
    astcode = fin.read()
    tree = ast.parse(astcode, mode='exec')
    print(f'The ast dump from injected tree is: {ast.dump(tree)}')
    for node in ast.walk(tree):
        #print(f'AST IV NODE :: {ast.dump(node)}')
        #ivector.append(ast.dump(node))
        try:
            param = node.keywords[0].arg        
            if param:
                ivector += param + " "
            val = str(node.keywords[0].value.value)
            if val:
                ivector += val + " "
        except:
            pass

print('Vectorization finished.')

print('\nivector contains:')
print(ivector)
print()

# Preparing the dataset
all_vulnerable_sentences = nltk.sent_tokenize(vvector)
all_injectable_sentences = nltk.sent_tokenize(ivector)

all_v_words = [nltk.word_tokenize(sent) for sent in all_vulnerable_sentences]
all_i_words = [nltk.word_tokenize(sent) for sent in all_injectable_sentences]

word2vecv = Word2Vec(all_v_words, min_count=2)
word2veci = Word2Vec(all_i_words, min_count=2)

print()

vvocabulary = word2vecv.wv.key_to_index
print(vvocabulary)

print()

ivocabulary = word2veci.wv.key_to_index
print(ivocabulary)

print()

#model = Word2Vec(sentences=common_texts, vector_size=100, window=5, min_count=1, workers=4)

#vmodel = gensim.models.KeyedVectors.load_word2vec_format(vvector,binary=False)
#imodel = gensim.models.KeyedVectors.load_word2vec_format(ivector,binary=False)

'''word_pairs = [
    ("False", "True"),
    ]'''

#injection_model = TranslationMatrix(vmodel, imodel, word_pairs=word_pairs)

#print('Injected:')
#trans_model.translate(["False"], topn=1)

#model.save("word2vec.model")