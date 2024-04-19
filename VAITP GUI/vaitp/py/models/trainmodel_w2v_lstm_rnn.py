
from gensim.models import KeyedVectors
from gensim.test.utils import datapath
'''
class CustomNodeVisitor(ast.NodeVisitor):
    def visit(self, node):
        print(node.__class__.__name__)
        return ast.NodeVisitor.visit(self, node)
'''

print('VAITP :: Train AI model [W2V LSTM RNN]')

#dataset paths
injectableFile = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/vaitp_dataset_diffs/manually_verified/injectable/injectable.txt"
vulnerableFile = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/vaitp_dataset_diffs/manually_verified/vulnerable/vulnerable.txt"

model_inj = KeyedVectors.load_word2vec_format(datapath(injectableFile))
model_vuln = KeyedVectors.load_word2vec_format(datapath(vulnerableFile))

word_pairs = [

    ("shell=False", "shell=True"), 
    ("etree.XMLParser(resolve_entities=False)", "etree.XMLParser(resolve_entities=True)"), 
    ("yaml.safe_load(data)", "yaml.load(data, Loader=yaml.Loader)"), 
    ("yaml.safe_load(var)", "yaml.load(var, Loader=yaml.Loader)"),  
    ("yaml.safe_load(filename)", "yaml.load(filename, Loader=yaml.Loader)"), 
    ("exec(quote(data))", "exec(data)"), 
    ("exec(quote(var))", "exec(var)"), 
    ("exec(quote(cmd))", "exec(cmd)"), 
    ("html.escape(data)", "data"), 
    ("html.escape(var)", "var"), 
    ("html.escape(cmd)", "cmd"), 
    ("quote(cmd)", "cmd"), 
    ("quote(data)", "data"), 
    ("quote(var)", "var"), 

]


#train
trans_model = TranslationMatrix(model_inj, model_vuln, word_pairs=word_pairs)

#test
print(f'\nTesting trained model translation:\n{trans_model.translate(["shell=False", "quote(var)"], topn=1)}')

''' AST FAILED TRY->
#vulnerable AST vector
vvector = ""#[]
#injectable AST vector
ivector = ""#[]

print()


#vectorize vulnerable dataset
print('Vectorizing vulnerable dataset...')
for astfile in glob.iglob(f'{dir_vulnerable}/*.txt'):
    print(f'Vectorizing AST: {astfile}')
    fin = open(astfile, "r")
    #vvector.append(fin.read())
    astcode = fin.read()
    tree = ast.parse(astcode, mode='exec')
    #print(f'The ast dump from vulnerable tree is: {ast.dump(tree)}')
    #CustomNodeVisitor().visit(tree)
    for node in ast.walk(tree):
        #print(f'AST VV NODE :: {ast.dump(node)}')
        #vvector.append(ast.dump(node))
        try:
            param = node.keywords[0].arg        
            if param:
                vvector += param + " "
                #vvector.append(param)
            val = str(node.keywords[0].value.value)
            if val:
                vvector += val + " "
                #vvector.append(val)
        except:
            pass


#vectorize injectable dataset
print('Vectorizing injectable dataset...')
for astfile in glob.iglob(f'{dir_injectable}/*.txt'):
    print(f'Vectorizing AST: {astfile}')
    fin = open(astfile, "r")
    #ivector.append(fin.read())
    astcode = fin.read()
    tree = ast.parse(astcode, mode='exec')
    #print(f'The ast dump from injected tree is: {ast.dump(tree)}')
    for node in ast.walk(tree):
        #print(f'AST IV NODE :: {ast.dump(node)}')
        #ivector.append(ast.dump(node))
        try:
            param = node.keywords[0].arg        
            if param:
                ivector += param + " "
               # ivector.append(param)
            val = str(node.keywords[0].value.value)
            if val:
                ivector += val + " "
                #ivector.append(val)
        except:
            pass



print('Vectorization finished.')


print('\nVulnerable vector contains:')
print(vvector)
print()

print('\nInjectable vector contains:')
print(ivector)
print()

# Preparing the dataset
all_vulnerable_sentences = nltk.sent_tokenize(vvector)
all_injectable_sentences = nltk.sent_tokenize(ivector)

all_v_words = [nltk.word_tokenize(sent) for sent in all_vulnerable_sentences]
all_i_words = [nltk.word_tokenize(sent) for sent in all_injectable_sentences]

word2vecv = Word2Vec(all_v_words, min_count=2)
word2veci = Word2Vec(all_i_words, min_count=2)

#Save the models
#word2vecv.save('vvectors.kv')
#word2veci.save('ivectors.kv')


print()

vvocabulary = word2vecv.wv.key_to_index
print(f'\nVulnerable vucabulary:\n{vvocabulary}')

print()

ivocabulary = word2veci.wv.key_to_index
print(f'\ninjectable vucabulary:\n{ivocabulary}')

print()

#model = Word2Vec(sentences=common_texts, vector_size=100, window=5, min_count=1, workers=4)

#vmodel = word2vecv.load('vvectors.kv', binary=False) 
#imodel = word2veci.load('ivectors.kv', binary=False)

#this step fails saing that word2vecv hasn't got a 'vector' object (althoug it printed correctly)
#vmodel = Word2Vec.load_word2vec_format(word2vecv, binary=True)
#imodel = Word2Vec.load_word2vec_format(word2veci, binary=True)


word_pairs = [
    (str("False"), str("True")),
    ]

injection_model = TranslationMatrix(word2vecv, word2veci, word_pairs=word_pairs)

print('\nInjected: \'False\' and expecting \'True\' as ouput:')
print(trans_model.translate(["False"], topn=1))

#model.save("word2vec.model")'''