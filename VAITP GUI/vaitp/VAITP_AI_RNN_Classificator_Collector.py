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
header = ['training epochs','testing epochs','density layer','training dataset_count','testing dataset_count','loss','accuracy','correct predictions','incorrect predictions']

#touch csv and add header
with open(csv_filename, 'w') as fp_csv:
    writer = csv.writer(fp_csv)
    writer.writerow(header)


total_training_epochs = 1900
total_testing_epochs = 2100
total_layer_density = 11


#Ai model parameters
training_epochs = 190
testing_epochs = 210
layer_density = 7 #mininum value: 3

for layer_density_it in range(layer_density, total_layer_density+1, 2):

    print(f':: Layer density Iterator :: {layer_density_it}')

    for testing_epochs_it in range(testing_epochs, total_testing_epochs+1,100):

        print(f':: Testing epochs Iterator :: {testing_epochs_it}')

        for training_epochs_it in range(training_epochs, total_training_epochs+1,100):

           
            '''
            if training_epochs_it<testing_epochs_it:
                if testing_epochs_it <= total_testing_epochs:
                    training_epochs_it=testing_epochs_it
                    break
            print(f':: Training epochs Iterator :: {training_epochs_it}')
            '''

            print(f'VAITP :: Training for {training_epochs_it} epochs, testing for {testing_epochs_it} epochs with {layer_density_it} layers of density.')

            #Run VAITP classification model and save output in the temp file
            cmd = subprocess.run(["python","VAITP_AI_RNN_Classificator_FitModel.py", str(training_epochs_it), str(testing_epochs_it), str(layer_density_it)], capture_output=True)
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
            correct_preditions=0
            incorrect_preditions=0

            for line in tmp_file_lines:
                line_num += 1

                #Get the Accuracy line output
                if line.find("Accuracy") != -1:
                    accuracy_value=line.split(" ")[1]
                
                #Get the "Found x files" 1st are the training and then the testing
                if line.find("Found") != -1:
                    if training_dataset_count==0:
                        training_dataset_count=line.split(" ")[1]
                    else:
                        testing_dataset_count=line.split(" ")[1]

                #Get the Loss    
                if line.find("loss:") != -1:
                    loss_value=line.split(" ")[7]

                #Get the correct preditions
                if line.find("Correct predictions:") != -1:
                    correct_preditions=line.split(" ")[2]

                #Get the incorrect preditions
                if line.find("Incorrect predictions:") != -1:
                    incorrect_preditions=line.split(" ")[2]


            tmp_file.close()

            if accuracy_value==0:
                accuracy_value="0%\n"

            #show this run results
            print('\tTraining results:')
            print(f'\t\tNumber of training epochs: {training_epochs_it}\n\
                    \tNumber of testing epochs: {testing_epochs_it}\n\
                    \tNumber of density layers: {layer_density_it}\n\
                    \tTraining dataset count: {training_dataset_count}\n\
                    \tTesting dataset count: {testing_dataset_count}\n\
                    \tLoss: {loss_value}\n\
                    \tAccuracy: {accuracy_value}\
                    \tCorrect predictions: {correct_preditions}\
                    \tIncorrect predictions: {incorrect_preditions}\
                    ')


            #save to the csv file
            with open(csv_filename, 'a') as fp_csv:
                writer = csv.writer(fp_csv)
                writer.writerow([training_epochs_it,testing_epochs_it,layer_density_it,training_dataset_count,testing_dataset_count,loss_value,accuracy_value.split("%\n")[0],int(correct_preditions),int(incorrect_preditions)])






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


msft.plot("training epochs","accuracy", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("training epochs","loss",  color='blue', kind='scatter', title = "VAITP AI Classificator")

msft.plot("testing epochs","accuracy", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("testing epochs","loss", color='blue', kind='scatter', title = "VAITP AI Classificator")

msft.plot("density layer","accuracy", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("density layer","loss", color='blue', kind='scatter', title = "VAITP AI Classificator")




msft.plot("training epochs","correct predictions", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("training epochs","incorrect predictions",  color='red', kind='scatter', title = "VAITP AI Classificator")

msft.plot("testing epochs","correct predictions", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("testing epochs","incorrect predictions", color='red', kind='scatter', title = "VAITP AI Classificator")

msft.plot("density layer","correct predictions", color='green', kind='scatter', title = "VAITP AI Classificator")
msft.plot("density layer","incorrect predictions", color='red', kind='scatter', title = "VAITP AI Classificator")








'''
msft.plot("accuracy", ["training epochs", "testing epochs", "density layer"], subplots=True)
msft.plot("loss", ["training epochs", "testing epochs", "density layer"], subplots=True)
msft.plot("correct predictions", ["training epochs", "testing epochs", "density layer"], subplots=True)
msft.plot("incorrect predictions", ["training epochs", "testing epochs", "density layer"], subplots=True)
'''
plt.show()

