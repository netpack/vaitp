import sys
import re
import shutil
import os.path

#Main VAITP injection module

def pyinject(pyfile="vuln01.py", vuln_txt="shell=False", inject_txt="shell=True"):

    #Inject inject_txt at vuln_txt in pyfile

    if re.search("\.py$",pyfile):

        try:
            #Open the file
            file = open(f"{pyfile}", 'rt')
            file_lines = file.readlines()
            #loop the lines
            for line in file_lines:
                #search if the vulnerability exists in this line
                print(f"inject_module :: {vuln_txt} :: {line}")
                if re.search(f"{vuln_txt}", line):
                    
                    print(f"Found Injection point at: {line}\nInjecting vulnerability...")

                    #backup but only if there isn't one already
                    if not os.path.isfile(f"{pyfile}.bkup"):
                        shutil.copy2(f"{pyfile}", f"{pyfile}.bkup")

                    #write injected file
                    shutil.copy2(f"{pyfile}", f"{pyfile}.temp")
                    fin = open(f"{pyfile}.temp", 'rt')
                    fout = open(f"{pyfile}", 'wt')
                    for l in fin:
                        newVulnLine = l.replace(f"{vuln_txt}".replace("\\",""), f"{inject_txt}")
                        if l.replace(f"{vuln_txt}", f"{inject_txt}") != newVulnLine:
                            l = f"{newVulnLine[0:-2]}\n" #//TODO: improve this... with regex
                        fout.write(l.replace(f"{vuln_txt}", f"{inject_txt}"))
                    fin.close()
                    fout.close()

                    #remove temp
                    os.remove(f"{pyfile}.temp")

            file.close()
            print("Done!")

        except:
            print(f"VAITP inject module: Can't open file {pyfile}")

    else:
        print("Argument 0 needs to be a python script")


if __name__ == '__main__':
    print("VAITP general injection module by Frédéric Bogaerts\n\n",
    "Inject into py file argv1 patched code argv2, vulnerable code argv3\n\n",
    "pyinject(patched_file.py, patch_str, vuln_str)")

    pyinject(sys.argv[1],sys.argv[2],sys.argv[3])