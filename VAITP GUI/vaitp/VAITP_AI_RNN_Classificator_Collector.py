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
header = ['fitting epochs','density layer','dropout','accuracy','loss','activation_mc','activation_ms','kernel_size','run']

#touch csv and add header
with open(csv_filename, 'w') as fp_csv:
    writer = csv.writer(fp_csv)
    writer.writerow(header)


#AI model fitting parameters

fitting_epochs = 70
layer_density = 3 #mininum value: 3
dropout = 2 #dropout is converted to float 1 = 0.1

total_fitting_epochs = 70
total_layer_density = 3
total_dropout = 2 #dropout is conv to float 9 = 0.9

fitting_step = 70
layer_step = 2
dropout_step = 1 # 0.1

#Configure activation functions
#A fixed activation can be set by adjusting the starting and total values
#Eg.: starting_activation_mc = 1 and total_activation_mc = 1 selects sigmoig+sigmoid
activation_functions_model_creation = ['relu','sigmoid','tanh','softmax','softplus','selu']
activation_functions_model_sequence = ['relu','sigmoid','tanh','softmax','softplus','selu']
starting_activation_mc = 1
starting_activation_ms = 3
total_activation_mc = 1
total_activation_ms = 3
activation_mc_step=1
activation_ms_step=1

#Filter units: 4, 8, 16, 32, 64, 128, 256
filter_terms=10
filter_result = list(map(lambda x: 2 ** x, range(filter_terms)))
filter_units_start=4

number_of_runs=3

#loop the density layers
for layer_density_it in range(layer_density, total_layer_density+1, layer_step):

        #loop the fitting epochs
        for fitting_epochs_it in range(fitting_epochs, total_fitting_epochs+1, fitting_step):

            #loop the dropouts
            for dropout_epochs_it in range(dropout, total_dropout+1, dropout_step):

                #loop the activation functions for the model creation
                for activation_mc_it in range(starting_activation_mc, total_activation_mc+1, activation_mc_step):

                    #loop the activation function for the model sequencing
                    for activation_ms_it in range(starting_activation_ms, total_activation_ms+1, activation_ms_step):


                        #loop the filter units
                        #for filter_units_it in range(2,filter_terms):

                        #loop the kernel size
                        #for kernel_size_it in range (1,30):

                            #filter_units = filter_result[filter_units_it]
                            filter_units = 128

                            #loop the runs
                            for run_it in range(1, number_of_runs+1, 1):

                                dropoutfloat = dropout_epochs_it/10
                                print(f'VAITP :: Run: {run_it}')
                                print(f'VAITP :: Model fitting epochs: {fitting_epochs_it}')
                                print(f'VAITP :: Density layers: {layer_density_it}')
                                print(f'VAITP :: Dropout: {dropoutfloat}')
                                print(f'VAITP :: Model creation activation function: {activation_functions_model_creation[activation_mc_it]}')
                                print(f'VAITP :: Model sequence activation function: {activation_functions_model_sequence[activation_ms_it]}')
                                print(f'VAITP :: Model filter units: {filter_units}')
                                print(f'VAITP :: Kernel size: {kernel_size_it}')

                                #Run VAITP classification model and save output in the temp file
                                cmd = subprocess.run(["python","VAITP_AI_RNN_Classificator_FitModel.py", str(fitting_epochs_it), str(layer_density_it), str(dropoutfloat),str(activation_mc_it),str(activation_ms_it),str(filter_units),str(kernel_size_it)], capture_output=True)
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
                                    if line.find("files for training") != -1:
                                            training_dataset_count=line.split(" ")[1]

                                    if line.find("files for validation") != -1:
                                            testing_dataset_count=line.split(" ")[1]


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
                                #'fitting epochs','density layer','dropout','accuracy','loss','activation_mc','activation_ms','run'
                                with open(csv_filename, 'a') as fp_csv:
                                    writer = csv.writer(fp_csv)
                                    writer.writerow([
                                        fitting_epochs_it,
                                        layer_density_it,
                                        dropout_epochs_it,
                                        accuracy_value.split("%\n")[0],
                                        loss_value,
                                        activation_functions_model_creation[activation_mc_it],
                                        activation_functions_model_sequence[activation_ms_it],
                                        kernel_size_it,
                                        run_it
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


msft.plot("fitting epochs","accuracy", color='green', kind='scatter', title = "VAITP AI Classificator")
#msft.plot("training epochs","loss",  color='blue', kind='scatter', title = "VAITP AI Classificator")

#msft.plot("testing epochs","accuracy", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("fitting epochs","loss", color='blue', kind='scatter', title = "VAITP AI Classificator")

msft.plot("density layer","accuracy", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("density layer","loss", color='blue', kind='scatter', title = "VAITP AI Classificator")


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

