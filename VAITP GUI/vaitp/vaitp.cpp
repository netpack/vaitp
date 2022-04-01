#include "vaitp.h"
#include "ui_vaitp.h"
#include "QFileDialog"
#include "QDirIterator"
#include "QSqlQuery"
#include "dbmanager.h"
#include <QDebug>
#include <QLoggingCategory>
#include <QMessageBox>
#include <QList>
#include "aimodule.h"
#include "detectionmodule.h"

/**
 * @brief VAITP::VAITP
 * @param parent: main VAITP process
 */
VAITP::VAITP(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::VAITP)
{
    ui->setupUi(this);
    qDebug() << "Welcome to VAITP by Frédéric Bogaerts!";

    //Open the db
    if(!db.isOpen()){
        qDebug()<<"Opening db...";
        db=QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName("../vaitp/vaitp.db");
        db.open();
    }

    //Reset the injection chain number
    chainNum=0;

}

/**
 * @brief VAITP::~VAITP
 */
VAITP::~VAITP()
{
    delete ui;
}

/**
 * @brief VAITP::on_bt_load_py_src_clicked
 * Locate .py script to analyze
 */
void VAITP::on_bt_load_py_src_clicked()
{
    QFileDialog dialog(this);
    dialog.setViewMode(QFileDialog::Detail);
    dialog.setFileMode(QFileDialog::AnyFile);
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open Python script"), "/home/", tr("Python scripts (*.py)"));
    QLineEdit* txt_py_src = ui->txt_py_src;
    txt_py_src->setText(fileName);
}

/**
 * @brief VAITP::on_bt_scan_py_clicked
 * Scan the selected .py script for possible injection points and vulnerabilities
 */
void VAITP::on_bt_scan_py_clicked()
{

    //clear the vulnerability list and the injection points list
    ui->lst_vulns->clear();
    ui->lst_injectionPoints->clear();

    //disable the attack button
    ui->bt_attack->setEnabled(false);


    //get the pie, hoo sorry, I meant py! :-)
    QString pyfile = ui->txt_py_src->text();
    if (pyfile.size()<4 || !(pyfile.endsWith(".py"))){
        ui->txt_output_sh1->appendHtml(tr("Invalid Python Script\n"));
    } else {

        //start scanning
        ui->txt_output_sh1->appendHtml(tr("Scanning Python Script... Please Wait...\n"));

        detectionModule dm;

        //detect and list vulnerabilities
        QStringList detectedVulnerabilities = dm.scanFileForVulnerabilities(pyfile);
        detectedVulnerabilities.removeDuplicates();
        for(int n=0; n<detectedVulnerabilities.count();n++){
            ui->lst_vulns->addItem(detectedVulnerabilities[n]);
        }

        //detect and list injection calls
        QStringList detectedInjectionPoints = dm.scanFileForInjectionCalls(pyfile);
        detectedInjectionPoints.removeDuplicates();
        for(int n=0; n<detectedInjectionPoints.count();n++){
            ui->lst_injectionPoints->addItem(detectedInjectionPoints[n]);
        }




        /*
        QFile inputFile(pyfile);
        QString sql_qry_vulns = "Select vulnerability from vulnerabilities";
        QSqlQuery sql;
        int line_num=0;
        QListWidget* vulnList = ui->lst_vulns;

        if (inputFile.open(QIODevice::ReadOnly)){

           QTextStream in(&inputFile);
           while (!in.atEnd()){

              //if we can read the file and while were not at the end of it we get the next line
              QString line = in.readLine();
              line_num++;

              //for this line check all known vulnerabilities and add them to the vulnerability list if present
              if(sql.exec(sql_qry_vulns)){
                  while(sql.next()){

                      QString vuln = sql.value(0).toString();
                      qDebug() << "Scanning: " << line << " for vuln: " << vuln;

                      // *Look for vulnerabilities* /
                      if (line.contains(vuln)){
                          qDebug() << "Adding vuln: " << vuln;


                          bool hasItem = false;
                          for(int i=0; i<vulnList->count(); i++){
                              if(vulnList->item(i)->text() == vuln){
                                hasItem = true;
                              }
                          }

                          if(!hasItem)
                            ui->lst_vulns->addItem(vuln);






                       //*Look for attack payloads* /

                          ui->lst_payload->clear();
                          QSqlQuery qry;
                          qry.prepare("Select payload from vulns where vulnerability like ?");
                          qry.bindValue(0,vuln);

                          qry.exec();

                          while(qry.next()){
                              ui->lst_payload->addItem(qry.value(0).toString());

                          }


                      }
                  }
              }






                //*Look for injection patches* /
                QString sql_qry_patches = "Select patch_start, patch, patch_end, injection from injections";
                if(sql.exec(sql_qry_patches)){
                    while(sql.next()){
                        QString patch_start = sql.value(0).toString();
                        QString patch = sql.value(1).toString();
                        QString patch_end = sql.value(2).toString();
                        QString injection = sql.value(3).toString();
                        qDebug() << "Scanning line " << line_num << ": " << line << " for patch: " << patch_start<<patch<<patch_end;

                        //Create regex
                        QRegularExpression re(QRegularExpression::escape(patch_start)+patch+QRegularExpression::escape(patch_end));
                        QRegularExpressionMatch match = re.match(line);
                        if(match.hasMatch()){
                            // add patch to patch list
                            ui->txt_output_sh1->appendHtml(tr("(0.0)  Patch regex matches: <h4>")+match.captured(0)+"</h4>");
                            QString item;
                            if(injection=="\\w+"){
                                ui->txt_output_sh1->appendHtml(tr("(0.0) Injection is regex \\w+"));

                                item = match.captured(0)+" :: "+match.captured(0).remove(patch_start).remove(patch_end) + " :: Line " + QString::number(line_num) + ": "+line.trimmed();

                            } else {
                                ui->txt_output_sh1->appendHtml(tr("(0.0) Injection is hard coded"));
                                item = patch_start+patch+patch_end+" :: "+injection + " :: Line " + QString::number(line_num) + ": "+line.trimmed();

                            }
                            ui->lst_injectionPoints->addItem(item);


                        }





                    }
                }




           }
           inputFile.close();
        }



        */

       ui->lbl_target->setText(pyfile);

       ui->txt_output_sh1->appendHtml(tr("Scanning Python Script... Done!"));

       //ui->bt_auto_daisyChain->setEnabled(true);










    }
}

/**
 * @brief VAITP::on_bt_inject_vuln_clicked
 * Inject a patch
 */
void VAITP::patchInjection(QString pyfile, bool isChained, QStringList patchList, bool isTemp)
{
    QString patch = patchList[0].trimmed();
    QString inj = patchList[1].trimmed();

    qDebug()<<"Selected file will be patched from: "<<patch<<" to: "<<inj;

    QString line = patchList[2].replace("Line","").trimmed().at(0);

    QString outputfilename="";
    QString time_format = "yyyy_MM_dd_HH_mm_ss";
    QDateTime a = QDateTime::currentDateTime();
    QString as = a.toString(time_format);
    QString thispyfile = pyfile.replace(".py","");


    if(isChained){

        chainNum++;
        qDebug()<<"chain Num:: "<<chainNum;

        if(isTemp){
            outputfilename = pyfile.replace(".py","")+"_temp_"+QString::number(chainNum)+".py";
            tempFiles.append(outputfilename);
        } else {
            QRegExp re("_temp_[0-9]*");
            outputfilename = pyfile.replace(".py","").replace(re,"")+"_injectedChain_"+as+".py";

        }


    } else {
        outputfilename = pyfile.replace(".py","")+"_injected_"+as+".py";

    }
     ui->lbl_target->setText(outputfilename);

     //ui->txt_output_sh1->appendHtml("Injected file output: "+outputfilename);
     if(!isTemp)
        ui->lst_injectedFiles->addItem(outputfilename);


    //if(QFile::copy(pyfile,outputfilename)){

        qDebug()<<"The pyfile is: "<<thispyfile+".py";
        qDebug()<<"The outputfilename is: "<<outputfilename;

            //QByteArray fileData;
            QFile file(thispyfile+".py");
            QFile out(outputfilename);
            int linenum = 0;
            QString text="";
            if(file.open(QIODevice::ReadOnly)){
                 if(out.open(QIODevice::ReadWrite)){
                     QTextStream in(&file);
                     while(!in.atEnd()){
                         linenum++;
                         QString linein = in.readLine()+"\n";
                         qDebug()<<"Read line["<<linenum<<"]: "<<linein;

                         if(line.toInt() == linenum){
                             linein.replace(patch, inj);
                         }
                         text.append(linein);
                     }
                     out.seek(0); // go to the beginning of the file
                     out.write(text.toUtf8());
                     out.close();
                 } else {
                     ui->txt_output_sh1->appendHtml("Unable to open out file "+outputfilename);
                 }
                 file.close();
            } else {
                ui->txt_output_sh1->appendHtml("Unable to open in file "+thispyfile+".py");
            }

            if(!isTemp)
                ui->txt_output_sh1->appendHtml("Injection file created: "+outputfilename);
}

void VAITP::on_bt_inject_vuln_clicked()
{
    ui->bt_inject_vuln->setEnabled(false);

    qDebug() << "COUNT: " << ui->lst_injectionPoints->count();

    //if there are possible injection points
    if(ui->lst_injectionPoints->count() > 0 && ui->lst_injectionPoints->currentItem() != NULL){

        ui->lbl_info->setText(tr("Injecting Python Script... Please Wait..."));

        //QString path = "/home/fred/msi/ano2/VAITP/python_exercises/vuln/";
        QString pyfile = ui->txt_py_src->text();

        QStringList patchList = ui->lst_injectionPoints->currentItem()->text().split("::");

        patchInjection(pyfile,false,patchList,false);


    }

}

void VAITP::on_lst_injectionPoints_itemClicked(QListWidgetItem *item)
{
    qDebug() << "Selected injection: " << item->text();
    ui->bt_inject_vuln->setEnabled(true);
    ui->bt_addToInjectionChain->setEnabled(true);
}

void VAITP::on_lst_vulns_itemClicked(QListWidgetItem *item)
{
    qDebug() << "Selected Vulnerability: " << item->text();

    //compose payloads list
    ui->lst_payload->clear();
    QSqlQuery qry;
    qry.prepare("Select payload from payloads");
    //qry.bindValue(0,item->text());

    ui->bt_attack->setEnabled(false);

    qry.exec();

    while(qry.next()){
        ui->lst_payload->addItem(qry.value(0).toString());
    }

    qDebug() << "SQL payloads :: " << qry.lastQuery();


    //get vulnerability description
    ui->txt_vulnDescription->clear();

    qry.prepare("Select description from vulnerabilities where vulnerability like ?");
    qry.bindValue(0,item->text());
    qry.exec();
    while(qry.next()){
        QString desc = qry.value(0).toString();
        qDebug() << "SQL desc in db :: " << desc;
        ui->txt_vulnDescription->insertPlainText(desc);
    }

    qDebug() << "SQL description :: " << qry.lastQuery();



}

void VAITP::on_bt_attack_clicked()
{
     ui->bt_attack->setEnabled(false);

     //if there is only one vulnerability the choise is obvious
     if(ui->lst_vulns->count()==1){
        ui->lst_vulns->setCurrentRow(0);
     }

     //if there is only one attack the choise is obvious
     if(ui->lst_payload->count()==1){
        ui->lst_payload->setCurrentRow(0);
     }

     if(ui->lst_vulns->currentItem() == NULL || ui->lst_payload->currentItem() == NULL){

         ui->txt_output_sh1->appendHtml("Please select a vulnerability and a payload to launch the attack.");

     } else {


           QString payload = ui->lst_payload->currentItem()->text();
           QString command("python");
           QStringList params;
           QString pyfile = ui->lbl_target->text();

           qDebug() << "Attacking file: " << pyfile;
           ui->txt_output_sh1->appendHtml("Attacking file: "+pyfile);

           params = QStringList() << pyfile << payload;

           QProcess p;
           p.start(command, params);
           p.waitForFinished();

           QString output(p.readAllStandardOutput());
           qDebug() << "Attack result: " << output;
           ui->txt_output_sh1->appendHtml("Attack output:<br>"+output);
           if(output.contains("root")){
               QString workingv = "Vulnerability: "+ui->lst_vulns->currentItem()->text()+ " :: Payload: "+payload+" :: File: "+pyfile;
               bool hasVP=false;
               for(int i=0; i<ui->lst_workingAttacks->count();i++){
                   if(ui->lst_workingAttacks->item(i)->text() == workingv){
                       hasVP=true;
                   }
               }
               if(!hasVP)
                ui->lst_workingAttacks->addItem(workingv);
           }

           p.close();



     }




}

void VAITP::on_bt_clearAll_clicked()
{
    ui->lst_injectionPoints->clear();
    ui->lst_payload->clear();
    ui->lst_vulns->clear();
    ui->txt_output_sh1->clear();
    ui->txt_vulnDescription->clear();
}

void VAITP::on_lst_payload_itemClicked(QListWidgetItem *item)
{
    qDebug()<<"Item selected: "<<item->text();
    ui->bt_attack->setEnabled(true);
}


void VAITP::on_lst_injectedFiles_itemClicked(QListWidgetItem *item)
{
    ui->bt_setInjectedFileAsTarget->setEnabled(true);
    ui->lbl_target->setText(item->text());
}


void VAITP::on_actionReScan_for_injected_files_triggered()
{
    /*get path for vulns*/

    /*get all py file that contain "_injected_" */

}


void VAITP::on_bt_addToInjectionChain_clicked()
{
    QString inp = ui->lst_injectionPoints->currentItem()->text();
    qDebug()<<"selected injection to add to chain: "<<inp;
    ui->lst_injectionsChain->addItem(inp);
    ui->bt_executeInjectionChain->setEnabled(true);
}




void VAITP::on_bt_executeInjectionChain_clicked()
{
    qDebug()<<"Executing injection chain...";
    ui->txt_output_sh1->appendHtml("Executing injection chain...");
    QString pyfile;
    //QString delFileName="";

    //patch all injections
    for(int ci=0; ci<ui->lst_injectionsChain->count();++ci){

        pyfile = ui->lbl_target->text();
        QStringList patchList = ui->lst_injectionPoints->item(ci)->text().split("::");

        if(ci==ui->lst_injectionsChain->count()-1){
            patchInjection(pyfile,true,patchList, false);
        } else {
            patchInjection(pyfile,true,patchList, true);
        }

    }

    //delete old ones
    qDebug()<<"To Delete::";
    for(int n=0; n<tempFiles.count(); n++){
        qDebug()<<tempFiles[n];
        QFile f(tempFiles[n]);
        f.remove();
    }

}


void VAITP::on_bt_clearInjectionChain_clicked()
{
    ui->lst_injectionsChain->clear();
}





void VAITP::on_bt_extract_cvefixes_vulns_clicked()
{
    ui->bt_extract_cvefixes_vulns->setEnabled(false);

    qDebug() << "[Extract CVEFixes vulnerabilites]";
    ui->txt_output_sh1_ai->appendHtml("Extracting CVEfixes vulnerabilities...");

    qDebug() << "deleting old temp files...";
    ui->txt_output_sh1_ai->appendHtml("Deleting old temp files...");
    qApp->processEvents();

    aimodule ai;
    ai.rm_temp();
    //ai.rm_old_dataset();

    ui->txt_output_sh1_ai->appendHtml("Opening CVEfixes db...");
    qApp->processEvents();

    ai.opencvefixesdb();


    /**
     *
     * Process vulnerabilities
     *
     */

    ui->txt_output_sh1_ai->appendHtml("Quering vulnerabilities. Please wait...");
    qApp->processEvents();

    //count Python vulnerabilities
    int num_python_vulns = ai.cvefixes_count_vulns();
    ui->txt_output_sh1_ai->appendHtml("Number of vulnerabilities loaded: "+QString("%1").arg(num_python_vulns));
    qApp->processEvents();

    //only continue if there are vulnerabilities in the database
    if(num_python_vulns>0){



        qDebug()<<"Processing CVSfixes vulnerabilities...";
        ui->txt_output_sh1_ai->appendHtml("Processing CVSfixes vulnerabilities...");
        qApp->processEvents();


        /**
         * @brief processedVulns
         * get all the vulns and extract into temp folder for manual review
         * separate ai test/trainig logic from data extraction process
         */

        QStringList processedVulns = ai.getAndProcess_dataset_vulnerabilities();
        QString vuln;
        foreach(vuln, processedVulns){
            ui->txt_output_sh1_ai->appendHtml("Vulnerability added: "+vuln);
            qApp->processEvents();
        }
        ui->txt_output_sh1_ai->appendHtml("Vulnerability dataset extracted sucessfuly.");
        qApp->processEvents();

         /*
          *

        //calc half of the dataset [low accuracy -> trying four fifths (80%) for training and 20% for testing]
        int num_half_vulns = num_python_vulns*0.8;
        int num_otherhalf_vulns = num_python_vulns*0.2;

        ui->txt_output_sh1_ai->appendHtml("Dividing vulnerability dataset in two for training and testing.");
        ui->txt_output_sh1_ai->appendHtml(QString("%1").arg(num_python_vulns) + " + " + QString("%1").arg(num_otherhalf_vulns));
        qApp->processEvents();

        //split half the dataset for training
        QStringList processedVulns = ai.get_dataset_first_half(num_half_vulns);
        QString vuln;
        foreach(vuln, processedVulns){
            ui->txt_output_sh1_ai->appendHtml("Training vulnerability added: "+vuln);
           qApp->processEvents();
        }
        ui->txt_output_sh1_ai->appendHtml("Training vulnerability dataset extracted sucessfuly.");
        qApp->processEvents();

        //remainder half of the dataset for testing
        QStringList processedVulnsTest = ai.get_dataset_second_half(num_otherhalf_vulns);
        foreach(vuln, processedVulns){
            ui->txt_output_sh1_ai->appendHtml("Testing vulnerability added: "+vuln);
            qApp->processEvents();
        }
        ui->txt_output_sh1_ai->appendHtml("Training vulnerability dataset extracted sucessfuly.");
        qApp->processEvents();

*/

    } else {
        qDebug()<<"There seam to be no Python vulnerabilities in CVSfixes db.. ?? ..";
        ui->txt_output_sh1_ai->appendHtml("There seam to be no Python vulnerabilities in CVSfixes db... aborting.");

    }






    /**
     *
     * Process patches
     *
     */


    //count Python patches
    int num_python_patches = ai.cvefixes_count_patches();
    ui->txt_output_sh1_ai->appendHtml("Number of patches loaded: "+QString("%1").arg(num_python_patches));
    qApp->processEvents();

    //only continue if there are patches in the database
    if(num_python_patches>0){



        qDebug()<<"Processing CVSfixes patches...";
        ui->txt_output_sh1_ai->appendHtml("Processing CVSfixes patches...");
        qApp->processEvents();

        QStringList processedVulns = ai.getAndProcess_dataset_patches();
        QString vuln;
        foreach(vuln, processedVulns){
            ui->txt_output_sh1_ai->appendHtml("Patch added: "+vuln);
            qApp->processEvents();
        }
        ui->txt_output_sh1_ai->appendHtml("Patches dataset extracted sucessfuly.");
        qApp->processEvents();

        /*
        //calc half of the dataset
        int num_half_patches = num_python_patches/2;
        ui->txt_output_sh1_ai->appendHtml("Dividing patches dataset in two. ["+QString("%1").arg(num_half_patches)+"]");
        qApp->processEvents();


        //split half the dataset for training
        QStringList processedVulns = ai.get_dataset_first_half_patches(num_half_patches);
        QString vuln;
        foreach(vuln, processedVulns){
            ui->txt_output_sh1_ai->appendHtml("Training vulnerability added: "+vuln);
            qApp->processEvents();
        }
        ui->txt_output_sh1_ai->appendHtml("Training vulnerability dataset extracted sucessfuly.");
        qApp->processEvents();


        //remainder half of the dataset for testing
        QStringList processedVulnsTest = ai.get_dataset_second_half_patches(num_half_patches);
        foreach(vuln, processedVulns){
            ui->txt_output_sh1_ai->appendHtml("Testing vulnerability added: "+vuln);
            qApp->processEvents();
        }
        ui->txt_output_sh1_ai->appendHtml("Testing vulnerability dataset extracted sucessfuly.");
        qApp->processEvents();
        */


    } else {
        qDebug()<<"There seam to be no Python vulnerabilities in CVSfixes db.. ?? ..";
        ui->txt_output_sh1_ai->appendHtml("There seam to be no Python vulnerabilities in CVSfixes db... aborting.");

    }





    ui->txt_output_sh1_ai->appendHtml("CVEfixes vulnerabilities and patches exctracted sucessfuly.");
    ui->bt_extract_cvefixes_vulns->setEnabled(true);
}





void VAITP::on_bt_train_ai_model_clicked()
{
    ui->bt_train_ai_model->setEnabled(false);

    ui->txt_output_sh1_ai->appendHtml("Starting AI RNN model training. Please wait...");
    qApp->processEvents();

    int spinVal = ui->sb_numEpochs->value();
    qDebug()<<"spinVal: "<<spinVal;

    int spinValTest = ui->sb_numEpochs_testing->value();
    int spinValDensity = ui->sb_numRNNDensity->value();

    ui->txt_output_sh1_ai->appendHtml("Number of training epochs set to: "+QString::number(spinVal));
    qApp->processEvents();

    ui->txt_output_sh1_ai->appendHtml("Number of testing epochs set to: "+QString::number(spinValTest));
    qApp->processEvents();

    ui->txt_output_sh1_ai->appendHtml("Number of RNN Density set to: "+QString::number(spinValDensity));
    qApp->processEvents();


    QProcess p;
    QStringList params;

    params << "../vaitp/trainmodel_textClassificationRNNs_vaitp.py" << QString::number(spinVal) << QString::number(spinValTest) << QString::number(spinValDensity);
    p.start("python", params);


    QString line;
    while(p.waitForReadyRead())
    {
        line = QString::fromUtf8(p.readLine());
        ui->txt_output_sh1_ai->appendHtml(line.replace("","").trimmed());
        qApp->processEvents();
    }

    if(!line.isEmpty()){
        ui->txt_output_sh1_ai->appendHtml(line.replace("","").trimmed());
        ui->txt_output_sh1_ai->appendHtml("AI RNN model trained sucesfully.");
    } else {
        ui->txt_output_sh1_ai->appendHtml("Error training AI RNN model.\nPlease check dependencies (Python, Tensorflow, and imports of AI RNN Python extenssion).");
    }


    ui->bt_train_ai_model->setEnabled(true);
}


void VAITP::on_bt_ai_extract_cvef_diffs_clicked()
{
    ui->bt_ai_extract_cvef_diffs->setEnabled(false);

    qDebug() << "[Extract CVEFixes diffs]";
    ui->txt_output_sh1_ai->appendHtml("Extracting CVEfixes diffs...");

    qDebug() << "deleting old temp files...";
    ui->txt_output_sh1_ai->appendHtml("Deleting old temp files...");
    qApp->processEvents();

    aimodule ai;
    ai.rm_temp_diffs();

    ui->txt_output_sh1_ai->appendHtml("Opening CVEfixes db...");
    qApp->processEvents();

    ai.opencvefixesdb();


    /**
     *
     * Process diffs
     *
     */

    ui->txt_output_sh1_ai->appendHtml("Quering diffs. Please wait...");
    qApp->processEvents();

    //count Python diffs
    int num_python_diffs = ai.cvefixes_count_diffs();
    ui->txt_output_sh1_ai->appendHtml("Number of diffs loaded: "+QString("%1").arg(num_python_diffs));
    qApp->processEvents();

    //only continue if there are diffs in the database
    if(num_python_diffs>0){

        qDebug()<<"Processing CVSfixes diffs...";
        ui->txt_output_sh1_ai->appendHtml("Processing CVSfixes diffs...");
        qApp->processEvents();

        QStringList processedVulns = ai.getAndProcess_dataset_diffs();
        QString vuln;
        foreach(vuln, processedVulns){
            ui->txt_output_sh1_ai->appendHtml("Diff added: "+vuln);
            qApp->processEvents();
        }
        ui->txt_output_sh1_ai->appendHtml("Diff dataset extracted sucessfuly.");
        qApp->processEvents();


    } else {
        qDebug()<<"There seam to be no Python diffs in CVSfixes db.. ?? ..";
        ui->txt_output_sh1_ai->appendHtml("There seam to be no Python diffs in CVSfixes db... aborting.");

    }




    ui->txt_output_sh1_ai->appendHtml("CVEfixes diffs exctracted sucessfuly.");
    ui->bt_extract_cvefixes_vulns->setEnabled(true);
}

