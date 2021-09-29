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

                      /*Look for vulnerabilities*/
                      if (line.contains(vuln)){
                          qDebug() << "Adding vuln: " << vuln;

                          /****
                           *
                           * Aqui estou a evitar que sejam adicionadas vulnerabilidades que já foram encontradas
                           * mas talvez fosse melhor ser ui->lst_vulns->addItem(vuln+" @ line: "+line) ??
                           *
                           * */
                          bool hasItem = false;
                          for(int i=0; i<vulnList->count(); i++){
                              if(vulnList->item(i)->text() == vuln){
                                hasItem = true;
                              }
                          }

                          if(!hasItem)
                            ui->lst_vulns->addItem(vuln);






                       /*Look for attack payloads*/

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






                /*Look for injection patches*/
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


       ui->txt_output_sh1->appendHtml(tr("Scanning Python Script... Done!"));

       //ui->bt_auto_daisyChain->setEnabled(true);










    }
}

/**
 * @brief VAITP::on_bt_inject_vuln_clicked
 * Inject a patch
 */
void VAITP::on_bt_inject_vuln_clicked()
{
    ui->bt_inject_vuln->setEnabled(false);

    qDebug() << "COUNT: " << ui->lst_injectionPoints->count();

    //if there are possible injection points
    if(ui->lst_injectionPoints->count() > 0 && ui->lst_injectionPoints->currentItem() != NULL){

        ui->lbl_info->setText(tr("Injecting Python Script... Please Wait..."));

        QString path = "/home/fred/msi/ano2/VAITP/python_exercises/vuln/";
        QString pyfile = ui->txt_py_src->text();


        QStringList patchList = ui->lst_injectionPoints->currentItem()->text().split("::");
        QString patch = patchList[0].trimmed();
        QString inj = patchList[1].trimmed();

        qDebug()<<"Selected file will be patched from: "<<patch<<" to: "<<inj;


        QString outputfilename = pyfile.replace(".py","")+"_injected_"+patchList[2].replace("Line","").trimmed().at(0)+".py";

         ui->txt_output_sh1->appendHtml("Injected file output: "+outputfilename);
         ui->lst_injectedFiles->addItem(outputfilename);


        //if(QFile::copy(pyfile,outputfilename)){



                QByteArray fileData;
                QFile file(pyfile+".py");
                QFile out(outputfilename);

                if(!file.open(QIODevice::ReadOnly))
                        qDebug()<<"Unable to open in file "<<pyfile+".py";

                if(!out.open(QIODevice::ReadWrite))
                        qDebug()<<"Unable to open out file "<<outputfilename;

                fileData = file.readAll();
                QString text(fileData);

                text.replace(patch, inj);

                out.seek(0); // go to the beginning of the file
                out.write(text.toUtf8());

                file.close();
                out.close();

                qDebug() << "Injection file created";


/*
                //add to gui
                bool hasI=false;
                for(int i=0; i<ui->lst_injectedFiles->count();i++){
                    if(ui->lst_injectedFiles->item(i)->text() == outputfilename){
                        hasI=true;
                    }
                }
                if(!hasI)
                 ui->lst_workingAttacks->addItem(outputfilename);*/
       // }




        /*ui->lst_injectionPoints->clear();*/


    }

}

void VAITP::on_bt_restore_pys_clicked()
{
    QString path = "/home/fred/msi/ano2/VAITP/python_exercises/vuln/";
    QString command("python");
    QStringList params = QStringList() << "restore_vulns.py";

    QProcess *process = new QProcess();
    process->startDetached(command, params, path);
    process->waitForFinished();
    process->close();

    ui->lbl_info->setText("The un-injected files were restored.");
}

void VAITP::on_lst_injectionPoints_itemClicked(QListWidgetItem *item)
{
    qDebug() << "Selected injection: " << item->text();
    ui->bt_inject_vuln->setEnabled(true);
}

void VAITP::on_lst_vulns_itemClicked(QListWidgetItem *item)
{
    qDebug() << "Selected Vulnerability: " << item->text();
    ui->lst_payload->clear();
    QSqlQuery qry;
    qry.prepare("Select payload from vulns where vulnerability like ?");
    qry.bindValue(0,item->text());



    ui->bt_attack->setEnabled(false);

    qry.exec();

    while(qry.next()){
        ui->lst_payload->addItem(qry.value(0).toString());
    }

    qDebug() << "SQL:: " << qry.lastQuery();

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
           QString pyfile = ui->txt_py_src->text();

           params = QStringList() << pyfile << payload;

           QProcess p;
           p.start(command, params);
           p.waitForFinished();

           QString output(p.readAllStandardOutput());
           qDebug() << "Attack result: " << output;
           ui->txt_output_sh1->appendHtml("Attack output:<br>"+output);
           if(output.contains("root")){
               QString workingv = "Vulnerability: "+ui->lst_vulns->currentItem()->text()+ " :: Payload: "+payload;
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
}

void VAITP::on_lst_payload_itemClicked(QListWidgetItem *item)
{
    qDebug()<<"Item selected: "<<item->text();
    ui->bt_attack->setEnabled(true);
}

