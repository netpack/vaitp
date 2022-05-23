#VAITP - train model classification rnn - Collector

import subprocess
import csv
import matplotlib.pyplot as plt
import matplotlib.cbook as cbook
import numpy as np
import pandas as pd
import time
from datetime import timedelta

time_start = time.time()

#temp file
tmp_filename = 'vaitp_trainmodel_output.temp'

#csv file
csv_filename = 'vaitp_trainmodel_output.csv'
#cve header
header = ['training_count','testing_count','optimizer','model_type','fitting_epochs','density_layer','dropout','activation_mc','activation_ms','strides','padding','output_dim','filters_units','kernel_size','vocab_size','max_seq','run','accuracy','loss']

#touch csv and add header
with open(csv_filename, 'w') as fp_csv:
    writer = csv.writer(fp_csv)
    writer.writerow(header)


#AI model fitting parameters

optimizer = "adam"
strides = 1
padding = 'valid'
#TODO: code loops for optimizer, strides and padding

model_types = ['bow','c1d','lstm']

#set the types of model to create
model_start = 0
model_total = 2 #0, 1, 2

fitting_epochs = 70
total_fitting_epochs = 80
fitting_step = 10

layer_density = 3 #mininum value: 3
total_layer_density = 5
layer_step = 2

dropout = 2 #dropout is converted to float 1 = 0.1
total_dropout = 3 #dropout is conv to float 9 = 0.9
dropout_step = 1 # 0.1

#Configure activation functions
#A fixed activation can be set by adjusting the starting and total values
#Eg.: starting_activation_mc = 1 and total_activation_mc = 1 selects sigmoig+sigmoid
activation_functions_model_creation = ['relu','sigmoid','tanh','softmax','softplus','selu']

starting_activation_mc = 1
total_activation_mc = 1
activation_mc_step=1

activation_functions_model_sequence = ['relu','sigmoid','tanh','softmax','softplus','selu']
starting_activation_ms = 3
total_activation_ms = 3
activation_ms_step=1

#Filter units: 4, 8, 16, 32, 64, 128, 256
#filter_terms=10
#filter_result = list(map(lambda x: 2 ** x, range(filter_terms)))
#filter_units_start=4

filter_start = 4#128
filter_total = 5#128
filter_step = 1

units_start = 4#128
units_total = 5#128
units_step = 1

kernel_start = 5
kernel_total = 6
kernel_step = 1

output_dim_start = 4#64
output_dim_total = 5#64
output_dim_step = 1

vocab_size_start = 5000
vocab_size_total = 5000
vocab_size_step = 1

max_seq_start = 450
max_seq_total = 450
max_seq_step = 1


number_of_runs=3

#loop the model types
for model_type_it in range(model_start, model_total+1, 1):
    
    print(f'__model_type_it__')

    model_type = model_types[model_type_it]

    #loop the density layers
    for layer_density_it in range(layer_density, total_layer_density+1, layer_step):

            print(f'__activation_edensity_layers_it__')

            #loop the fitting epochs
            for fitting_epochs_it in range(fitting_epochs, total_fitting_epochs+1, fitting_step):

                print(f'__activation_epochs_it__')

                #loop the dropouts
                for dropout_epochs_it in range(dropout, total_dropout+1, dropout_step):

                    print(f'__activation_dropout_it__')
                    #loop the activation functions for the model creation
                    for activation_mc_it in range(starting_activation_mc, total_activation_mc+1, activation_mc_step):

                        print(f'__activation_mc_it__')

                        #loop the activation function for the model sequencing
                        for activation_ms_it in range(starting_activation_ms, total_activation_ms+1, activation_ms_step):

                            print(f'__activation_ms_it__')

                            #loop the filter units
                            #for filter_units_it in range(2,filter_terms):

                            #loop the kernel size
                            this_kernel_start = kernel_start
                            this_kernel_total = kernel_total
                            if model_type != 'c1d':
                                #only c1d has this
                                this_kernel_start = 5
                                this_kernel_total = 5

                            for kernel_size_it in range (this_kernel_start,this_kernel_total+1,kernel_step):

                                print(f'__kernel_size_it__')
                                #filter_units = filter_result[filter_units_it]
                                
                                for units_it in range (units_start,units_total+1,units_step):

                                    print(f'__units_it__')

                                    for filters_it in range (filter_start,filter_total+1,filter_step):

                                        print(f'__filter_it__')

                                        filter_units = filters_it
                                
                                        for output_dim_it in range (output_dim_start,output_dim_total+1,output_dim_step):

                                            print(f'__output_dim_it__')
                                

                                            for vocab_size_it in range (vocab_size_start,vocab_size_total+1,vocab_size_step):

                                                print(f'__vocab_size_it__')

                                                for max_seq_it in range (max_seq_start,max_seq_total+1,max_seq_step):

                                                    print(f'__max_seq_it__')



                                                #loop the runs
                                                for run_it in range(1, number_of_runs+1, 1):

                                                    dropoutfloat = dropout_epochs_it/10
                                                    print(f'VAITP :: Run: {run_it}')
                                                    print(f'VAITP :: Model type: {model_type}')
                                                    print(f'VAITP :: Model fitting epochs: {fitting_epochs_it}')
                                                    print(f'VAITP :: Density layers: {layer_density_it}')
                                                    print(f'VAITP :: Dropout: {dropoutfloat}')
                                                    if model_type.upper() != 'BOW':
                                                        print(f'VAITP :: Model creation activation function: {activation_functions_model_creation[activation_mc_it]}')
                                                    print(f'VAITP :: Model sequence activation function: {activation_functions_model_sequence[activation_ms_it]}')
                                                    if model_type.upper() == 'C1D':
                                                        print(f'VAITP :: Model filters: {filter_units}')
                                                        print(f'VAITP :: Kernel size: {kernel_size_it}')
                                                    if model_type.upper() == 'LSTM':
                                                        print(f'VAITP :: Units: {units_it}')
                                                    if model_type.upper() != 'BOW':   
                                                        print(f'VAITP :: Output dimension: {output_dim_it}')
                                                    print(f'VAITP :: Vocabulary size: {vocab_size_it}')
                                                    print(f'VAITP :: Max sequence size: {max_seq_it}')

                                                    #Run VAITP classification model and save output in the temp file
                                                    cmd = subprocess.run(["python","VAITP_AI_RNN_Classificator_FitModel.py",str("-t"),str(model_type),str("-e"),str(fitting_epochs_it),str("-l"),str(layer_density_it),str("-d"),str(dropoutfloat),str("-a"),str(activation_mc_it),str("-b"),str(activation_ms_it), "-f",str(filter_units),str("-k"),str(kernel_size_it),str("-u"),str(units_it),str("-o"),str(output_dim_it),str("-v"),str(vocab_size_it),str("-m"),str(max_seq_it)], capture_output=True, check=True)
                                                    cmdout = cmd.stdout.decode()
                                                    tmp_file = open(tmp_filename,'w')
                                                    tmp_file.writelines(cmdout)
                                                    tmp_file.close()

                                                    #print("VAITP :: Model trained and tested.")

                                                    #Get the output to process line by line
                                                    tmp_file = open(tmp_filename,'r')
                                                    tmp_file_lines = tmp_file.readlines()

                                                    #obtain these variables values from the output of the model
                                                    line_num = 0
                                                    training_dataset_count = 0
                                                    testing_dataset_count = 0
                                                    loss_value = 0
                                                    accuracy_value = 0
                                                    tp=0
                                                    tn=0
                                                    #correct_preditions=0
                                                    #incorrect_preditions=0

                                                    for line in tmp_file_lines:
                                                        line_num += 1
                                        
                                                        #Get the "Found x files" 1st are the training and testing
                                                        if line.find("VAITP total training data-set count :: ") != -1:
                                                                training_dataset_count=line.split(" ")[6]

                                                        if line.find("VAITP total testing data-set count ::") != -1:
                                                                testing_dataset_count=line.split(" ")[6]


                                                        #Get the Accuracy line output
                                                        if line.find("VAITP final model accuracy:") != -1:
                                                            accuracy_value=line.split(" ")[4]
                                                    

                                                        #Get the Loss    
                                                        if line.find("VAITP final model loss:") != -1:
                                                            loss_value=line.split(" ")[4]

                                                        
                                                        #Get the incorrect preditions
                                                        if line.find("VAITP wrong training data-set count") != -1:
                                                            incorrect_preditions=line.split(" ")[6]

                                                        #Get the correct preditions
                                                        if line.find("VAITP correct training data-set count") != -1:
                                                            correct_preditions=line.split(" ")[6]
                                                        

                                                        #Get the true positives
                                                        #if line.find("TP:") != -1:
                                                            #tp=line.split(" ")[1].replace('\n','')

                                                        #Get the true negatives
                                                        #if line.find("TN:") != -1:
                                                            #tn=line.split(" ")[1].replace('\n','')

                                                    tmp_file.close()

                                                    if accuracy_value==0:
                                                        accuracy_value="0%\n"

                                                    #show this run results
                                                    print('\tTraining results:')
                                                    print(f'\t\tNumber of training epochs: {fitting_epochs_it}\n\
                                                            \tNumber of testing epochs: {fitting_epochs_it}\n\
                                                            \tNumber of density layers: {layer_density_it}\n\
                                                            \tTraining dataset count: {training_dataset_count}\n\
                                                            \tTesting dataset count: {testing_dataset_count}\n\
                                                            \tLoss: {loss_value}\n\
                                                            \tAccuracy: {accuracy_value}\n\
                                                            \tCorrect preditions from training data-set: {correct_preditions}\n\
                                                            \tIncorrect predictions from training data-set: {incorrect_preditions}\n\
                                                            ')


                                                    #save to the csv file
                                                    #'training_count','testing_count','optimizer','model_type','fitting_epochs','density_layer','dropout','activation_mc','activation_ms','strides','padding','output_dim','filters_units','kernel_size','vocab_size','max_seq','run','accuracy','loss'
                                                    if model_type.upper() == 'BOW':
                                                        with open(csv_filename, 'a') as fp_csv:
                                                            writer = csv.writer(fp_csv)
                                                            writer.writerow([
                                                                training_dataset_count,
                                                                testing_dataset_count,
                                                                optimizer,
                                                                model_type,
                                                                fitting_epochs_it,
                                                                layer_density_it,
                                                                dropoutfloat,
                                                                "NA",
                                                                activation_functions_model_sequence[activation_ms_it],
                                                                "NA",
                                                                "NA",
                                                                "NA",
                                                                "NA",
                                                                "NA",
                                                                vocab_size_it,
                                                                max_seq_it,
                                                                run_it,
                                                                accuracy_value.split("%\n")[0],
                                                                loss_value,
                                                            ])
                                                    elif model_type.upper() == 'C1D':
                                                        with open(csv_filename, 'a') as fp_csv:
                                                            writer = csv.writer(fp_csv)
                                                            writer.writerow([
                                                                training_dataset_count,
                                                                testing_dataset_count,
                                                                optimizer,
                                                                model_type,
                                                                fitting_epochs_it,
                                                                layer_density_it,
                                                                dropoutfloat,
                                                                activation_functions_model_creation[activation_mc_it],
                                                                activation_functions_model_sequence[activation_ms_it],
                                                                strides,
                                                                padding,
                                                                filters_it,
                                                                kernel_size_it,
                                                                output_dim_it,
                                                                vocab_size_it,
                                                                max_seq_it,
                                                                run_it,
                                                                accuracy_value.split("%\n")[0],
                                                                loss_value,
                                                            ])
                                                    else:
                                                        with open(csv_filename, 'a') as fp_csv:
                                                            writer = csv.writer(fp_csv)
                                                            writer.writerow([
                                                                training_dataset_count,
                                                                testing_dataset_count,
                                                                optimizer,
                                                                model_type,
                                                                fitting_epochs_it,
                                                                layer_density_it,
                                                                dropoutfloat,
                                                                activation_functions_model_creation[activation_mc_it],
                                                                activation_functions_model_sequence[activation_ms_it],
                                                                strides,
                                                                padding,
                                                                units_it,
                                                                kernel_size_it,
                                                                output_dim_it,
                                                                vocab_size_it,
                                                                max_seq_it,
                                                                run_it,
                                                                accuracy_value.split("%\n")[0],
                                                                loss_value,
                                                            ])






localpath = "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/"
#Anush comment above and change here:
#localpath = ""

#plot
fname = cbook.get_sample_data(localpath+csv_filename, asfileobj=False)
with cbook.get_sample_data(localpath+csv_filename) as file:
    msft = pd.read_csv(file)
    
time_now = time.time()
time_delta = time_now-time_start
print(f'Collector tests finished in {timedelta(seconds=time_delta)}')


msft.plot("fitting_epochs","accuracy", color='green', kind='scatter', title = "VAITP AI Classificator")
#msft.plot("training epochs","loss",  color='blue', kind='scatter', title = "VAITP AI Classificator")

#msft.plot("testing epochs","accuracy", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("fitting_epochs","loss", color='blue', kind='scatter', title = "VAITP AI Classificator")

msft.plot("density_layer","accuracy", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("density_layer","loss", color='blue', kind='scatter', title = "VAITP AI Classificator")


msft.plot(["activation_mc","activation_ms"],"accuracy", color='green', kind='scatter', title = "VAITP AI Classificator", subplots=True)
msft.plot(["activation_mc","activation_ms"],"loss", color='blue', kind='scatter', title = "VAITP AI Classificator", subplots=True)



#msft.plot("training epochs","correct predictions", color='green', kind='scatter', title = "VAITP AI Classificator")
#msft.plot("training epochs","incorrect predictions",  color='red', kind='scatter', title = "VAITP AI Classificator")

#msft.plot("testing epochs","correct predictions", color='green', kind='scatter', title = "VAITP AI Classificator")
#msft.plot("testing epochs","incorrect predictions", color='red', kind='scatter', title = "VAITP AI Classificator")

#msft.plot("density layer","correct predictions", color='green', kind='scatter', title = "VAITP AI Classificator")
#msft.plot("density layer","incorrect predictions", color='red', kind='scatter', title = "VAITP AI Classificator")








'''
msft.plot("accuracy", ["training epochs", "testing epochs", "density layer"], subplots=True)
msft.plot("loss", ["training epochs", "testing epochs", "density layer"], subplots=True)
msft.plot("correct predictions", ["training epochs", "testing epochs", "density layer"], subplots=True)
msft.plot("incorrect predictions", ["training epochs", "testing epochs", "density layer"], subplots=True)
'''
plt.show()

