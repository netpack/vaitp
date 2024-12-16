#include "vaitp.h"
#include "ui_vaitp.h"
#include "QFileDialog"
#include "QDirIterator"
#include "QSqlQuery"
/*#include "dbmanager.h"*/
#include <QDebug>
#include <QLoggingCategory>
#include <QMessageBox>
#include <QList>
#include "aimodule.h"
#include "detectionmodule.h"
#include <QPrinter>
#include <QDesktopServices>
#include <QTimer>
#include <QPlainTextEdit>
#include <QScrollBar>

int vaitp_loaded=0;
int number_of_vulnerabilities_found=0;
int number_of_scanned_files=0;
int number_of_injection_points_found=0;
int number_of_rx_injection_points_found=0;
int number_of_ai_injection_points_found=0;
int number_of_noninj_by_regex=0;
int number_of_vuln_by_regex=0;
QString inj_re="";
QString inj_ai="";
const int typingDelay = 25;

// Typing effect
QTimer* typingTimer;
int currentCharacterIndex;
QString animatedText;
QTextOption textOption;

// Define source path
#ifdef Q_OS_MAC
    QString basepath = "../../../../../"; //this is needed to account for vaitp.app/Content/MacOS/ structure in MacOS
#elif defined(Q_OS_LINUX)
    QString basepath = "../../"; //TODO: Review this path under GNU/Linux
#else
    QString basepath = "..\..\"; //TODO: Review this path under Windows
#endif

// Slot to type next character
void VAITP::typeNextCharacter() {
    qApp->processEvents();
    if (currentCharacterIndex < animatedText.length()) {
        ui->txt_output_sh1->insertPlainText(animatedText.at(currentCharacterIndex));
        ++currentCharacterIndex;
        QScrollBar* vScrollBar = ui->txt_output_sh1->verticalScrollBar();
        vScrollBar->setValue(vScrollBar->maximum());
    } else {
        typingTimer->stop();

    }
}

//Slot to animate the typing effect in the output sh1
void VAITP::animateTyping(QString aString){
    animatedText = aString;
    currentCharacterIndex = 0;

    typingTimer->start(typingDelay);
}


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

    textOption.setAlignment(Qt::AlignJustify);
    ui->txt_output_sh1->document()->setDefaultTextOption(textOption);

    //Connect the typing timer with the slot to be called
    typingTimer = new QTimer(this);
    connect(typingTimer, &QTimer::timeout, this, &VAITP::typeNextCharacter);

    //Animated welcome message
//    textOption.setAlignment(Qt::AlignCenter);
//    ui->txt_output_sh1->document()->setDefaultTextOption(textOption);

    QString lineToCenter = "Welcome to VAITP! v1.2 Beta [with MacOS deployment!]";

    // Calculate the number of spaces needed to center the line
    int totalWidth = ui->txt_output_sh1->viewport()->width();
    QFontMetrics fontMetrics(ui->txt_output_sh1->font());
    int lineWidth = fontMetrics.horizontalAdvance(lineToCenter);
    int spacesToAdd = (totalWidth - lineWidth) / fontMetrics.horizontalAdvance(" ");

    // Prepend the necessary spaces to the line
    QString centeredLine = QString(spacesToAdd / 2, ' ') + lineToCenter;

    animateTyping(centeredLine);




    //Open the db
    if(!db.isOpen()){
        qDebug()<<"Opening db...";
        db=QSqlDatabase::addDatabase("QSQLITE");
        QString dbpath = "vaitp.db";
        dbpath = basepath+"vaitp.db";
        if (!QFile::exists(dbpath)) {
            qDebug() << "Failed to find db in:" << dbpath;
            ui->txt_vaitp_log_path->setText("Failed to find db in: "+dbpath);
        }

        db.setDatabaseName(dbpath);
        db.open();

    }

    //Reset the injection chain number
    chainNum=0;


    QSqlQuery query;
    QString vaitp_models_path="";
    QString vaitp_log_path="";
    int ai_classificator_selected=0;
    int use_ai_classificator=0;
    int use_ai_s2s=0;
    int change_dir_on_attack=0;
    QStringList models;

    //load the value of vaitp_log_path
    if(query.exec("SELECT vaitp_log_path from settings")){
        while(query.next()){
            vaitp_log_path = query.value(0).toString();
            ui->txt_vaitp_log_path->setText(vaitp_log_path);
        }
    }
    qDebug()<<"VAITP AI models path set to: "<<vaitp_models_path;

    //load the value of vaitp_ai_models_path
    if(query.exec("SELECT vaitp_ai_models_path from settings")){
        while(query.next()){
            vaitp_models_path = query.value(0).toString();
            ui->txt_vaitp_models_path->setText(vaitp_models_path);
        }
    }
    qDebug()<<"VAITP AI models path set to: "<<vaitp_models_path;


    //load the db version
    if(query.exec("SELECT db_version from settings")){
        while(query.next()){
            QString db_version = QString::number(query.value(0).toInt());
            qDebug() << "Database version: " << db_version;

            ui->txt_output_sh1->appendHtml(tr("Loaded VAITP DB version: " )+db_version);
        }
    }
    qDebug()<<"VAITP AI use_ai_classificator set to: "<<use_ai_classificator;


    //load the value of use_ai_classificator
    if(query.exec("SELECT use_ai_classificator from settings")){
        while(query.next()){
            use_ai_classificator = query.value(0).toInt();
            if(use_ai_classificator==2)
                ui->checkBox_use_vaitp_ai_classificator->setChecked(true);
        }
    }
    qDebug()<<"VAITP AI use_ai_classificator set to: "<<use_ai_classificator;


    //load the value of use_ai_s2s
    if(query.exec("SELECT use_ai_s2s from settings")){
        while(query.next()){
            use_ai_s2s = query.value(0).toInt();
            if(use_ai_s2s==2)
                ui->checkBox_use_vaitp_ai_s2s->setChecked(true);
        }
    }
    qDebug()<<"VAITP AI use_ai_s2s set to: "<<use_ai_s2s;


    //load the value of change_dir_on_attack
    if(query.exec("SELECT change_dir_on_attack from settings")){
        while(query.next()){
            change_dir_on_attack = query.value(0).toInt();
            if(change_dir_on_attack==2)
                ui->checkBox_change_dir_on_attack->setChecked(true);
        }
    }
    qDebug()<<"VAITP AI use_ai_s2s set to: "<<use_ai_s2s;



    //get all ai classificator models and populate ui
    if(!vaitp_models_path.isEmpty()){
        QDir dir(vaitp_models_path);
        dir.setFilter(QDir::Dirs);
        QList <QFileInfo> fileList = dir.entryInfoList();
        qDebug()<<"VAITP AI model path file list: "<<fileList;
        for (int i = 0; i < fileList.size(); ++i) {
            QFileInfo fileInfo = fileList.at(i);
            if (fileInfo.suffix() == "tfv") {
                qDebug()<<"VAITP AI model found: "<<fileInfo.absoluteFilePath();
                if(!fileInfo.baseName().contains("s2s"))
                    ui->comboBox_vaitp_ai_classificator->addItem(fileInfo.completeBaseName());
            }
        }
    }



    //load the value of ai_classificator_selected
    if(query.exec("SELECT ai_classificator_selected from settings")){
        while(query.next()){
            ai_classificator_selected = query.value(0).toInt();
            ui->comboBox_vaitp_ai_classificator->setCurrentIndex(ai_classificator_selected);
            qDebug()<<"VAITP AI ai_classificator_selected set to: "<<use_ai_classificator;
        }
    }

    //load payloads
    ui->lst_payload->clear();
    QSqlQuery qry;
    qry.prepare("Select payload from payloads");
    ui->bt_attack->setEnabled(false);
    qry.exec();
    while(qry.next()){
        QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/playstation.png"),qry.value(0).toString());
        ui->lst_payload->addItem(itm);
        qApp->processEvents();
    }

    qDebug() << "SQL payloads :: " << qry.lastQuery();


    vaitp_loaded=1;
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
void VAITP::vaitp_scan_py_file(QString aFile)
{
        qDebug()<<"VAITP :: Getting some pie... :-) ...";

        QString pyfile = aFile;
        int s2s_inj_limit = ui->txt_s2s_inj_limit->value();

        if (pyfile.size()<4 || !(pyfile.endsWith(".py"))){
            ui->txt_output_sh1->appendHtml(tr("Invalid Python Script\n"));
        } else {

            //set the expected classification based on the folder the script is located in
            //this is just to allow us to calculate tp/tn/fp/fn
            QString expected_classification = "injectable";
            if(pyfile.contains("/noninjectable/")){
                expected_classification = "noninjectable";
            }
            /*else if(pyfile.contains("/vulnerable")) { //this can stay for a future version
                expected_classification = "vulnerable";
            }*/


            ui->txt_output_sh1->appendHtml(tr("Based on it's path, the file is expected to be: ")+expected_classification);


            //int number_of_vulns_in_list = ui->lst_vulns->count();


            //start scanning
            ui->txt_output_sh1->appendHtml(tr("Scanning Python Script... Please Wait...\n"));

            qDebug()<<"VAITP :: Scanning vulnerabilities";
            ui->txt_output_sh1->appendHtml(tr("Scanning vulnerabilities..."));


            number_of_scanned_files++;
            ui->lbl_scanned_files->setText("Scanned files: ["+QString::number(number_of_scanned_files)+"]");
            qApp->processEvents();


            detectionModule dm;

            //detect and list vulnerabilities
            QStringList detectedVulnerabilities = dm.scanFileForVulnerabilities(pyfile);
            detectedVulnerabilities.removeDuplicates();
            for(int n=0; n<detectedVulnerabilities.count();n++){
                QString vulnerability = detectedVulnerabilities[n]+" :: "+ui->txt_py_src->text();
                QListWidgetItem *itm = new QListWidgetItem(QIcon(":/logo/icon_48.png"),vulnerability);
                ui->lst_vulns->addItem(itm);
                number_of_vulnerabilities_found++;
                ui->lbl_vulnerabilities_found->setText("Vulnerabilities: ["+QString::number(number_of_vulnerabilities_found)+"]");
                qApp->processEvents();
            }

            qDebug()<<"VAITP :: Scanning injection calls";
            ui->txt_output_sh1->appendHtml(tr("Scanning injection calls..."));
            qApp->processEvents();

            //detect and list injection calls
            QStringList detectedInjectionPoints = dm.scanFileForInjectionCalls(pyfile);
            detectedInjectionPoints.removeDuplicates();
            for(int n=0; n<detectedInjectionPoints.count();n++){
                QString injection_point = detectedInjectionPoints[n]+" :: "+ui->txt_py_src->text();
                QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/nonai.png"),injection_point);
                ui->lst_injectionPoints->addItem(itm);
                number_of_injection_points_found++;
                number_of_rx_injection_points_found++;
                ui->lbl_injection_points->setText("Injection points: ["+QString::number(number_of_injection_points_found)+"] (RX: "+QString::number(number_of_rx_injection_points_found)+" AI: "+QString::number(number_of_ai_injection_points_found)+")");
                inj_re+=detectedInjectionPoints[n]+"<br>";
                qApp->processEvents();
            }

            QString scanned = "Regex Scan :: "+ui->txt_py_src->text();
            if(detectedInjectionPoints.isEmpty()){
                //If no injection points where added to the injection points list
                //The file can only be noninjectable or vulnerable

                //int new_number_of_vulns_in_list = ui->lst_vulns->count();

                //if the number of vulnerabilities is not the same, classify as vulnerable else as noninj
               // if(number_of_vulns_in_list == new_number_of_vulns_in_list){
                    //non inj
                    scanned+=" :: noninjectable";
                    number_of_noninj_by_regex++;
                    if(ui->checkBox_calc_regex_inj_tfpn->isChecked()){

                        if(expected_classification == "injectable"){
                            //FN - A injectable file predicted as non-injectable
                            int v = ui->metrics_regex_inj_fn->text().toInt()+1;
                            ui->metrics_regex_inj_fn->setText(QString::number(v));
                        } else if(expected_classification == "noninjectable"){
                            //TN - A non-injectable file predicted as non-injectable
                            int v = ui->metrics_regex_inj_tn->text().toInt()+1;
                            ui->metrics_regex_inj_tn->setText(QString::number(v));
                        }


                    }
                /* } else {
                    //vuln
                    scanned+=" :: vulnerable";
                    number_of_vuln_by_regex++;

                    if(ui->checkBox_calc_regex_inj_tfpn->isChecked()){

                        if(expected_classification == "injectable"){
                            //FN - A injectable file predicted as vulnerable
                            int v = ui->metrics_regex_inj_fn->text().toInt()+1;
                            ui->metrics_regex_inj_fn->setText(QString::number(v));
                        } else if(expected_classification == "noninjectable"){
                            //FN - A vulnerable file predicted as non-injectable
                            int v = ui->metrics_regex_inj_fn->text().toInt()+1;
                            ui->metrics_regex_inj_fn->setText(QString::number(v));
                        } else if(expected_classification == "vulnerable"){
                            //TP - A vulnerable file predicted as vulnerable
                            int v = ui->metrics_regex_inj_tp->text().toInt()+1;
                            ui->metrics_regex_inj_tp->setText(QString::number(v));
                        }


                    }

                } */

            } else {
                scanned+=" :: injectable";
                if(ui->checkBox_calc_regex_inj_tfpn->isChecked()){

                    if(expected_classification == "injectable"){
                        //TP - An injectable file predicted as injectable
                        int v = ui->metrics_regex_inj_tp->text().toInt()+1;
                        ui->metrics_regex_inj_tp->setText(QString::number(v));
                    } else if(expected_classification == "noninjectable"){
                        //FP - An injectable file predicted as non-injectable
                        int v = ui->metrics_regex_inj_fp->text().toInt()+1;
                        ui->metrics_regex_inj_fp->setText(QString::number(v));
                    }


                }
            }
            QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/python2.png"),scanned);
            ui->lst_scanned_files->addItem(itm);

            if(ui->checkBox_use_vaitp_ai_classificator->isChecked()){

                qDebug()<<"VAITP :: Scanning with AI classificator...";
                ui->txt_output_sh1->appendHtml(tr("Scanning with AI classificator..."));
                qApp->processEvents();

                QString selected_ai_classificator_model = ui->comboBox_vaitp_ai_classificator->currentText();

                ui->txt_output_sh1->appendHtml(tr("Selected AI classificator: ")+selected_ai_classificator_model);
                qApp->processEvents();

                ui->lbl_ai_classificator_run->setText(tr("Scanning..."));
                qApp->processEvents();

                aimodule ai;
                ai.set_file_to_scan(pyfile);
                QString selected_ai_classificator_model_wpath = ui->txt_vaitp_models_path->text()+"/"+selected_ai_classificator_model+".tfv";

                qDebug()<<"AI Classificator with path: "<<selected_ai_classificator_model_wpath;

                QStringList predicted_lable = ai.run_classificator_model(selected_ai_classificator_model_wpath);
                ui->lbl_ai_classificator_run->setText(predicted_lable[0]);
                QStringList probable_inj_points;
                QStringList translated_inj_points;

                if(predicted_lable[0]=="injectable"){

                    qDebug()<<"VAITP :: Scanning with AI classificator revealed an injectable script!";
                    ui->txt_output_sh1->appendHtml(tr("Scanning with AI classificator revealed an injectable script!"));

                    qApp->processEvents();

                    int ig=0;
                    for(QString ip: predicted_lable){
                        ig++;
                        if(ig==1)
                            continue; //ignore "injectable" in [0]
                        ui->txt_output_sh1->appendHtml(tr("Possible injection point detected by AI Classificator model: ")+ip);
                        qApp->processEvents();
                        probable_inj_points.append(ip);
                        if(ui->checkBox_add_partial_injection_points->isChecked()){
                            QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/ai.png"),ip);
                            ui->lst_injectionPoints->addItem(itm);

                            number_of_injection_points_found++;
                            number_of_ai_injection_points_found++;
                        }
                    }




                    //use s2s to try to translate the qstringlist
                    if(ui->checkBox_use_vaitp_ai_s2s->isChecked()){

                        ui->txt_output_sh1->appendHtml(tr("Translating probable injection points with AI S2S. Please wait..."));
                        qApp->processEvents();


                        QStringList translated_injection_points = ai.run_s2s_model(probable_inj_points,s2s_inj_limit);
                        try {
                            for(QString tr_ip: translated_injection_points){

                                ui->txt_output_sh1->appendHtml(tr("Possible injection point translated by AI S2S model: ")+tr_ip);
                                qApp->processEvents();
                                translated_inj_points.append(tr_ip);
                            }
                        }  catch (QString err) {
                            qDebug()<<"Error2:: "<<err;
                        }

                        //compose injection entries
                        try {
                            int ipn=0;
                            for(QString tr:translated_injection_points){

                                qApp->processEvents();
                                QString p_inj_p = probable_inj_points[ipn];
                                QString t_inj_p = translated_injection_points[ipn];
                                QString new_inj_string = p_inj_p+" :: "+t_inj_p;
                                qDebug()<<"New injection string composed: "<<new_inj_string;
                                //line number //line content
                                int line_number=0;
                                QString line="";
                                QFile file(ai.getSelectedFile());
                                if ( file.open(QIODevice::ReadOnly | QIODevice::Text) ){

                                    QTextStream stream( &file );

                                    while ( !stream.atEnd() ){
                                        line_number++;
                                        line = stream.readLine();
                                        //qDebug()<<"IF AI SCANN :: Line: "<<line<<" ::has:: "<<p_inj_p;
                                        if(line.contains(p_inj_p)){
                                            qDebug()<<"VAITP AI INJ TR :: Found line number: "<<line_number;
                                            break;
                                        }
                                    }
                                new_inj_string += " :: Line "+QString::number(line_number)+": "+line+" :: "+ai.getSelectedFile();
                                file.close();
                                QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/ai.png"),new_inj_string);
                                ui->lst_injectionPoints->addItem(itm);

                                number_of_injection_points_found++;
                                number_of_ai_injection_points_found++;
                                ui->lbl_injection_points->setText("Injection points: ["+QString::number(number_of_injection_points_found)+"] (RX: "+QString::number(number_of_rx_injection_points_found)+" AI: "+QString::number(number_of_ai_injection_points_found)+")");

                                qApp->processEvents();

                                inj_ai+=new_inj_string+"<br>";
                                ipn++;
                                }

                            }
                        }  catch (QString err) {
                            qDebug()<<"err22: "<<err;
                        }

                    } else {
                        ui->txt_output_sh1->appendHtml(tr("S2S disabled in settings. Possible injection points from AI will be ignored."));
                        qApp->processEvents();
                    }


                }


            } else {
                ui->lbl_ai_classificator_run->setText("(disabled)");
            }



            //use gpt
            if(ui->checkBox_enable_VAITP_SecurePythonGPT->isChecked()){

                ui->txt_output_sh1->appendHtml(tr("Generating security information for the Python code with SecurePythonGPT. Please wait..."));
                qApp->processEvents();

                aimodule ai;
                QStringList gpt_response = ai.securePythonGPT(pyfile);
                try {

                    //ui->txt_output_sh1->appendHtml(tr("<p style='blue'>SecurePythonGPT: </span>"));

                    for(QString gpt_resp: gpt_response){

                        animateTyping(gpt_resp);
                        qApp->processEvents();

                    }
                }  catch (QString err) {
                    qDebug()<<"Error2:: "<<err;
                }

            }


           qDebug()<<"VAITP :: Updating GUI..";
           qApp->processEvents();

           ui->lbl_target->setText(pyfile);

           ui->txt_output_sh1->appendHtml(tr("Scanning Python Script... Done!\n\n"));

           qApp->processEvents();

           //ui->bt_auto_daisyChain->setEnabled(true);












        }
    }

void VAITP::on_bt_scan_py_clicked()
{
    qDebug()<<"VAITP :: Start scanning";


    //clear the vulnerability list and the injection points list
    ui->lst_vulns->clear();
    ui->lst_injectionPoints->clear();
    ui->lbl_ai_classificator_run->setText("");

    //disable the attack button
    ui->bt_attack->setEnabled(false);

    //get the file selected by the user
    QString pyfile = ui->txt_py_src->text();

    //actually scan the file
    vaitp_scan_py_file(pyfile);

    //Obtain the predicted lable
    QString predicted_label = ui->lbl_ai_classificator_run->text();

    //Append the result to the output window
    ui->txt_output_sh1->appendHtml("Adding Scanned file: "+pyfile+" which was predicted as "+predicted_label+"<br><br>");
    qApp->processEvents();



    QString item_text = "AI Scan :: " + pyfile+" :: "+predicted_label;
    //add to scanned files list
    QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/python2.png"),item_text);
    ui->lst_scanned_files->addItem(itm);

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
            QRegularExpression re("_temp_[0-9]*");
            outputfilename = pyfile.replace(".py","").replace(re,"")+"_injectedChain_"+as+".py";

        }


    } else {
        outputfilename = pyfile.replace(".py","")+"_injected_"+as+".py";

    }
     ui->lbl_target->setText(outputfilename);

     //ui->txt_output_sh1->appendHtml("Injected file output: "+outputfilename);
     if(!isTemp){
        QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/bug.png"),outputfilename);
        ui->lst_injectedFiles->addItem(itm);
    }

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

        if(patchList.count()!=4){
             ui->txt_output_sh1->appendHtml("The injection point does not respect the format: [patched] :: [injected] :: [Line number]: [Original line content] :: [File path]");
        } else {
            pyfile = patchList[3].trimmed();
            patchInjection(pyfile,false,patchList,false);
        }




    }

}

void VAITP::on_lst_injectionPoints_itemClicked(QListWidgetItem *item)
{
    qDebug() << "Selected injection: " << item->text();
    ui->bt_inject_vuln->setEnabled(true);
    ui->bt_addToInjectionChain->setEnabled(true);
    item->setFlags(item->flags() | Qt::ItemIsEditable);
}

void VAITP::on_lst_vulns_itemClicked(QListWidgetItem *item)
{
    qDebug() << "Selected Vulnerability: " << item->text();

    QString selectedVuln = item->text().split(" :: ")[0];

    QSqlQuery qry;

    //get vulnerability description
    ui->txt_vulnDescription->clear();

    qry.prepare("Select description from vulnerabilities where vulnerability like ?");
    qry.bindValue(0,selectedVuln);
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
     //if(ui->lst_vulns->count()==1){
       // ui->lst_vulns->setCurrentRow(0);
     //}

     //if there is only one attack the choise is obvious
     if(ui->lst_payload->count()==1){
        ui->lst_payload->setCurrentRow(0);
     }

     if(ui->lst_payload->currentItem() == NULL){

         ui->txt_output_sh1->appendHtml("Please select a payload to launch the attack.");

     } else {


           QString command("python3");



           QString payload = ui->lst_payload->currentItem()->text();

           QStringList params;
           QString pyfile = ui->lbl_target->text();

           qDebug() << "Attacking file: " << pyfile;
           ui->txt_output_sh1->appendHtml("Attacking file: "+pyfile);

           params = QStringList() << pyfile << payload;

           QFileInfo pyinfo(pyfile);
           QProcess p;
           if(ui->checkBox_change_dir_on_attack->isChecked()){
                p.setWorkingDirectory(pyinfo.absolutePath());
           }
           p.start(command, params);
           p.waitForReadyRead(120000);
           p.waitForFinished(120000);

           QString output(p.readAll());
           qDebug() << "Attack result: " << output;
           ui->txt_output_sh1->appendHtml("Attack output:<br>"+output);
           //qApp->processEvents();

           if(output.contains("root")){
               qDebug() << "Attack result contains 'root': " << output;
               QString vuln=ui->lst_vulns->item(0)->text();

               if(ui->lst_vulns->selectedItems().size() != 0)
                    vuln=ui->lst_vulns->currentItem()->text();

               QString workingv = "Vulnerability: "+vuln+ " :: Payload: "+payload+" :: File: "+pyfile;
               bool hasVP=false;
               try {
                   for(int i=0; i<ui->lst_workingAttacks->count();i++){
                       if(ui->lst_workingAttacks->item(i)->text() == workingv){
                           hasVP=true;
                       }
                   }
               }  catch (QString err) {
                   qDebug()<<"Err :::: "<<err;
               }

               if(!hasVP){
                    qDebug()<<"wv::::::::"<<workingv;
                    QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/diamond-alt.png"),workingv);
                    ui->lst_workingAttacks->addItem(itm);
               }
           }
           qApp->processEvents();

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
    QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/cogs.png"),inp);
    ui->lst_injectionsChain->addItem(itm);
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
        QStringList patchList = ui->lst_injectionsChain->item(ci)->text().split("::");

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




/*
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
*/

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



void VAITP::on_bt_extract_common_words_clicked()
{
    ui->bt_extract_common_words->setEnabled(false);

    qDebug() << "[Extract CVEFixes CommonWords]";
    ui->txt_output_sh1_ai->appendHtml("Extracting CVEfixes common words...");

    ui->txt_output_sh1_ai->appendHtml("Opening CVEfixes db...");
    qApp->processEvents();

    aimodule ai;
    ai.opencvefixesdb();


    /**
     *
     * Process common words
     *
     */

    ui->txt_output_sh1_ai->appendHtml("Quering common words. Please wait...");
    qApp->processEvents();

    //count Python entries
    int num_python_entries = ai.cvefixes_count_diffs(); //diffs is always the same value as entries
    ui->txt_output_sh1_ai->appendHtml("Number of entries loaded: "+QString("%1").arg(num_python_entries));
    qApp->processEvents();

    //only continue if there are entries in the database
    if(num_python_entries>0){

        qDebug()<<"Processing CVSfixes common words...";
        ui->txt_output_sh1_ai->appendHtml("Processing CVSfixes common words...");
        qApp->processEvents();

        QStringList processedVulns = ai.getAndProcess_dataset_commonwords();
        /*
        QString vuln;
        foreach(vuln, processedVulns){
            ui->txt_output_sh1_ai->appendHtml("Common word added: "+vuln);
            qApp->processEvents();
        }*/
        ui->txt_output_sh1_ai->appendHtml("Common words dataset extracted sucessfuly.");
        qApp->processEvents();


    } else {
        qDebug()<<"There seam to be no Python entries in CVSfixes db.. ?? ..";
        ui->txt_output_sh1_ai->appendHtml("There seam to be no Python entries in CVSfixes db... aborting.");

    }




    ui->txt_output_sh1_ai->appendHtml("CVEfixes diffs exctracted sucessfuly.");
    ui->bt_extract_cvefixes_vulns->setEnabled(true);
}


void VAITP::on_bt_load_ai_models_path_clicked()
{
    //show the directory dialog
    QFileDialog dialog(this);
    dialog.setViewMode(QFileDialog::Detail);
    dialog.setFileMode(QFileDialog::AnyFile);
    QString fileName = QFileDialog::getExistingDirectory(this, tr("Open VAITP AI model"), "/home/");
    QLineEdit* txt_py_src = ui->txt_vaitp_models_path;
    txt_py_src->setText(fileName);


    QSqlQuery query;
    query.prepare("UPDATE settings set vaitp_ai_models_path=:path;");
    query.bindValue(":path",fileName);
    qDebug()<<"SQL VAITP :: "<<query.exec();



}

int save_tmp_state=0;
void VAITP::on_checkBox_use_vaitp_ai_classificator_stateChanged(int arg1)
{
    qDebug()<<"state changed to "<<arg1;
    QSqlQuery query;
    query.prepare("UPDATE settings set use_ai_classificator=:use_ai_clas;");
    query.bindValue(":use_ai_clas",arg1);
    query.exec();

    if(arg1==0){
        //if it's disabled we've got to disable the s2s also
        save_tmp_state = ui->checkBox_use_vaitp_ai_s2s->isChecked();//save state
        ui->checkBox_use_vaitp_ai_s2s->setChecked(false);
        ui->checkBox_use_vaitp_ai_s2s->setEnabled(false);
    } else{
        ui->checkBox_use_vaitp_ai_s2s->setEnabled(true);
        ui->checkBox_use_vaitp_ai_s2s->setChecked(save_tmp_state);//load state
    }
}

//TODO: save the value of ai_classificator_selected


void VAITP::on_checkBox_use_vaitp_ai_s2s_stateChanged(int arg1)
{
    qDebug()<<"state changed to "<<arg1;
    QSqlQuery query;
    query.prepare("UPDATE settings set use_ai_s2s=:use_ai_s2s;");
    query.bindValue(":use_ai_s2s",arg1);
    query.exec();

    if(arg1==2){
        //if it's enabled we've got to enable the classificator also
        ui->checkBox_use_vaitp_ai_classificator->setChecked(true);
    }
}


void VAITP::on_bt_extract_one_line_clicked()
{
    ui->bt_extract_one_line->setEnabled(false);

    qDebug() << "[Extract CVEFixes one line diffs]";
    ui->txt_output_sh1_ai->appendHtml("Extracting CVEfixes one line diffs...");

    ui->txt_output_sh1_ai->appendHtml("Quering one line diffs. Please wait...");
    qApp->processEvents();

    aimodule ai;
    ai.opencvefixesdb();

    //count Python diffs
    int num_python_diffs = ai.cvefixes_count_oneline_diffs();
    ui->txt_output_sh1_ai->appendHtml("Number of one line diffs loaded: "+QString("%1").arg(num_python_diffs));
    qApp->processEvents();

    //only continue if there are diffs in the database
    if(num_python_diffs>0){

        qDebug()<<"Processing CVSfixes one line diffs...";
        ui->txt_output_sh1_ai->appendHtml("Processing CVSfixes one line diffs...");
        qApp->processEvents();

        QStringList processedVulns = ai.getAndProcess_dataset_oneline_diffs();
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




void VAITP::on_bt_load_log_output_path_clicked()
{
    //show the directory dialog
    QFileDialog dialog(this);
    dialog.setViewMode(QFileDialog::Detail);
    dialog.setFileMode(QFileDialog::AnyFile);
    QString fileName = QFileDialog::getExistingDirectory(this, tr("Open VAITP Log output folder"), "/home/");
    QLineEdit* txt_py_src = ui->txt_vaitp_log_path;
    txt_py_src->setText(fileName);


    QSqlQuery query;
    query.prepare("UPDATE settings set vaitp_log_path=:path;");
    query.bindValue(":path",fileName);
    qDebug()<<"SQL VAITP :: "<<query.exec();


}


void VAITP::on_comboBox_vaitp_ai_classificator_currentIndexChanged(int index)
{
    if(vaitp_loaded==1){
        qDebug()<<"index changed to "<<index;
        QSqlQuery query;
        query.prepare("UPDATE settings set ai_classificator_selected=:ai_classificator_selected;");
        query.bindValue(":ai_classificator_selected",index);
        query.exec();
    }

}




void VAITP::on_bt_setInjectedFileAsTarget_clicked()
{
    ui->lbl_target->setText(ui->lst_injectedFiles->currentItem()->text());
}




void VAITP::on_checkBox_change_dir_on_attack_stateChanged(int arg1)
{
    //change_dir_on_attack
    qDebug()<<"state changed to "<<arg1;
    QSqlQuery query;
    query.prepare("UPDATE settings set change_dir_on_attack=:change_dir_on_attack;");
    query.bindValue(":change_dir_on_attack",arg1);
    query.exec();
}


void VAITP::on_actionImport_payloads_to_vaitp_db_triggered()
{
    QFileDialog dialog(this);
    dialog.setViewMode(QFileDialog::Detail);
    dialog.setFileMode(QFileDialog::AnyFile);
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open payloads file"), "/home/", tr("text files (*.txt)"));

    QFile inputFile(fileName);
    ui->txt_output_sh1->appendHtml("Opening payload file: "+fileName);
    qApp->processEvents();
    if (inputFile.open(QIODevice::ReadOnly))
    {
       QTextStream in(&inputFile);
       while (!in.atEnd())
       {
          QString line = in.readLine();
          qDebug() << "PAYLOAD ADD :: "<<line;
          ui->txt_output_sh1->appendHtml("New Payload: "+line);
          qApp->processEvents();
          QSqlQuery query;

          query.prepare("select payload from payloads where payload like :payload;");
          query.bindValue(":payload",line);
          bool has_payload = false;
          if(query.exec()){
              if(query.next()){
                  has_payload=true;
              }
          }
          if(!has_payload){
              query.prepare("INSERT into payloads VALUES(NULL,:payload);");
              query.bindValue(":payload",line);
              query.exec();
              ui->txt_output_sh1->appendHtml("Payload added to db.");
              qApp->processEvents();
          } else {
              ui->txt_output_sh1->appendHtml("Payload was already in db.");
              qApp->processEvents();
          }


       }
       inputFile.close();
    }
}


void VAITP::on_actionClear_all_outputs_and_lists_triggered()
{
    ui->lst_injectionPoints->clear();
    ui->lst_payload->clear();
    ui->lst_vulns->clear();
    ui->txt_output_sh1->clear();
    ui->txt_vulnDescription->clear();
    ui->lst_scanned_files->clear();

    number_of_vulnerabilities_found=0;
    number_of_scanned_files=0;
    number_of_injection_points_found=0;
    number_of_rx_injection_points_found=0;
    number_of_ai_injection_points_found=0;
    number_of_noninj_by_regex=0;
    number_of_vuln_by_regex=0;
    ui->lbl_scanned_files->setText("Scanned files: [0]");
    ui->lbl_vulnerabilities_found->setText("Vulnerabilities: [0]");
    ui->lbl_injection_points->setText("Injection points: [0] (RX: 0 AI: 0)");

}




void VAITP::on_bt_load_py_src_folder_clicked()
{
    QFileDialog dialog(this);
    dialog.setViewMode(QFileDialog::Detail);
    dialog.setFileMode(QFileDialog::Directory);
    QString fileName = QFileDialog::getExistingDirectory(this, tr("Open a directory to scan all python files"), "/home/");
    ui->txt_py_src_folder->setText(fileName);
}


void VAITP::on_bt_scan_py_folder_clicked()
{
    //get the string with the path of the folder to scan
    QString path_to_scan = ui->txt_py_src_folder->text();
    qDebug()<<"Path to scan: "<<path_to_scan;

    //show what dir to scan in the bottom output
    ui->txt_output_sh1->appendHtml("Directory selected for scanning: "+path_to_scan);
    qApp->processEvents();


    //check if the user wants to scan subdirs
    QDirIterator it(path_to_scan, QStringList() << "*.py", QDir::Files, ui->checkBox_scan_subdirs->isChecked() ? QDirIterator::Subdirectories : QDirIterator::NoIteratorFlags);


    //loop though each file of the (sub)folder
//    int injectable_files_found_regex = 0;
//    int noninjectable_files_found_regex = 0;
//    int vulnerable_files_found_regex = 0;
    int injectable_files_found_ai = 0;
    int noninjectable_files_found_ai = 0;
    //int vulnerable_files_found_ai = 0;

    while (it.hasNext()){

        QString this_file = it.next();

        qDebug() << "this file to scan: "<<this_file;


        //set the file as src (it's used after)
        ui->txt_py_src->setText(this_file);

        //scan the file
        vaitp_scan_py_file(this_file);

        //post-process
        //check path and caculate metrics
        QString expected_classification = "injectable";
        if(this_file.contains("/noninjectable/")){
            expected_classification = "noninjectable";
        }
        QString predicted_label = ui->lbl_ai_classificator_run->text();


        ui->txt_output_sh1->appendHtml("Adding Scanned file: "+this_file+" which was predicted as "+predicted_label);
        if (predicted_label == "injectable"){injectable_files_found_ai++;}
        //else if(predicted_label == "vulnerable"){vulnerable_files_found_ai++;}
        else{noninjectable_files_found_ai++;}


        if(predicted_label == "injectable" && expected_classification == "injectable"){
            //TP
            int v = ui->metrics_ai_inj_tp->text().toInt()+1;
            ui->metrics_ai_inj_tp->setText(QString::number(v));
        } else if(predicted_label == "noninjectable" && expected_classification == "noninjectable"){
            //TN
            int v = ui->metrics_ai_inj_tn->text().toInt()+1;
            ui->metrics_ai_inj_tn->setText(QString::number(v));
        } else if(predicted_label == "noninjectable" && expected_classification == "injectable"){
            //FN
            int v = ui->metrics_ai_inj_fn->text().toInt()+1;
            ui->metrics_ai_inj_fn->setText(QString::number(v));
        } else if(predicted_label == "injectable" && expected_classification == "noninjectable"){
            //FP
            int v = ui->metrics_ai_inj_fp->text().toInt()+1;
            ui->metrics_ai_inj_fp->setText(QString::number(v));
        }


        //calculate regex accuracy
        float r_a = float((ui->metrics_regex_inj_tp->text().toInt()+ui->metrics_regex_inj_tn->text().toInt())*100)/(ui->metrics_regex_inj_tp->text().toInt()+ui->metrics_regex_inj_tn->text().toInt()+ui->metrics_regex_inj_fp->text().toInt()+ui->metrics_regex_inj_fn->text().toInt());
        ui->lbl_accuracy_regex->setText(QString::number(r_a,'f',2)+"%");

        //calculate ai accuracy
        float r_b = float((ui->metrics_ai_inj_tp->text().toInt()+ui->metrics_ai_inj_tn->text().toInt())*100)/(ui->metrics_ai_inj_tp->text().toInt()+ui->metrics_ai_inj_tn->text().toInt()+ui->metrics_ai_inj_fp->text().toInt()+ui->metrics_ai_inj_fn->text().toInt());
        ui->lbl_accuracy_ai->setText(QString::number(r_b,'f',2)+"%");


        qApp->processEvents();

        QString item_text = "AI :: " + this_file+" :: "+predicted_label;

        //add to scanned files list
        QListWidgetItem *itm = new QListWidgetItem(QIcon(":/lineicons-free-basic-3.0/png-files/python2.png"),item_text);
        ui->lst_scanned_files->addItem(itm);



    }
    qDebug()<<"Injectable files by AI: "<<injectable_files_found_ai;
    //qDebug()<<"Vulnerable files by AI: "<<vulnerable_files_found_ai;
    qDebug()<<"NonInjectable files by AI: "<<noninjectable_files_found_ai;
    qDebug()<<"Injectable files by Regex: "<<number_of_injection_points_found;
    //qDebug()<<"Vulnerable files by Regex: "<<number_of_vuln_by_regex;
    int nonInjwithVuln = number_of_noninj_by_regex+number_of_vuln_by_regex;
    qDebug()<<"NonInjectable files by Regex: "<<nonInjwithVuln;
//    cout<<"Injectable files: ";



}



void VAITP::on_actionAbout_triggered()
{
    qDebug()<<"VAITP - Vulnerability attack and injection tool in Python. Frédéric Bogaerts 2022.";
    QMessageBox m;
    m.about(this,"About VAITP","Vulnerability Attack and Injection Tool in Python.<br><br>"
                               "Development: Frédéric Bogaerts (info@netpack.pt)<br>"
                               "Colaboration: Anush Deokar (deokar.1@iitj.ac.in)<br>"
                               "Orientation: PhD. Naghmeh Ivaki & PhD. José Fonseca<br><br>"
                               "Departamento de Engenharia Informática<br>"
                               "Universidade de Coimbra - Portugal<br>"
                               "20-07-2023<br>"
                               "VAITP v1.1");


}


void VAITP::on_actionExport_PDF_report_triggered()
{
    qDebug()<<"Extract report clicked";
    ui->txt_output_sh1->appendHtml("VAITP report creation started. Please wait...");
    qApp->processEvents();


    QDateTime dateTime = dateTime.currentDateTime();
    QString now = dateTime.toString("yyyy-MM-dd-HH-mm-ss");

    QString filesScanned="";
    for(int f=0; f<ui->lst_scanned_files->count(); f++){
        filesScanned+=ui->lst_scanned_files->item(f)->text()+"<br><br>";
    }

    QString vulns ="";
    for(int vu=0; vu<ui->lst_vulns->count();vu++){
        vulns+=ui->lst_vulns->item(vu)->text()+"<br><br>";
    }



    QString chainedinjs ="";
    for(int vu=0; vu<ui->lst_injectionsChain->count();vu++){
        chainedinjs+=ui->lst_injectionsChain->item(vu)->text()+"<br><br>";
    }

    QString injfiles ="";
    for(int vu=0; vu<ui->lst_injectedFiles->count();vu++){
        injfiles+=ui->lst_injectedFiles->item(vu)->text()+"<br><br>";
    }


    QString workingattacks ="";
    for(int vu=0; vu<ui->lst_workingAttacks->count();vu++){
        workingattacks+=ui->lst_workingAttacks->item(vu)->text()+"<br><br>";
    }

    //create print html ///<br><h3>VAITP</h3>
    QString html = "<div style='text-align:center'>"
                   "<img src=':/logo/icon_96.png'/>"
                   "</div><br>"
                   "<div style='text-align:center'>"
                   "<h2>VAITP</h2>"
                   "</div>"
                   "<br><div style='text-align:right'>"
                   "<h5>VAITP Report: "+now+"</h5>"
                   "</div><br>"
                   "<div>"
                   "<p><strong>Scanned files:</strong> <br>"+filesScanned+"<br></p>"
                   "<p><strong>Vulnerabilities found:</strong> <br>"+vulns+"<br></p>"
                   "<p><strong>Regex-based injection points found:</strong> <span style='font-size:100px'>(format: [injectable code :: vulnerable code :: Line number :: original line])</span> <br>"+inj_re+"<br></p>"
                   "<p><strong>Use VAITP AI Classificator model:</strong> <br>"+(ui->checkBox_use_vaitp_ai_classificator->isChecked() ? "Yes":"No")+"<br></p>"
                   "<p><strong>Use VAITP AI Classificator model path:</strong> <br>"+ui->txt_vaitp_models_path->text()+"<br></p>"
                   "<p><strong>VAITP AI Classificator model selected:</strong> <br>"+ui->comboBox_vaitp_ai_classificator->currentText()+"<br></p>"
                   "<p><strong>Use VAITP AI Sequence2Sequence model:</strong> <br>"+(ui->checkBox_use_vaitp_ai_s2s->isChecked() ? "Yes":"No")+"<br></p>"
                   "<p><strong>VAITP AI Classificator injection points found:</strong> <span style='font-size:100px'>(format: [injectable code :: vulnerable code :: Line number :: original line])</span> <br>"+inj_ai+"<br></p>"
                   "<p><strong>List of chained injections:</strong> <span style='font-size:100px'>(format: [injectable code :: vulnerable code :: Line number :: original line])</span> <br>"+chainedinjs+"<br></p>"
                   "<p><strong>List of injected files:</strong> <br>"+injfiles+"<br></p>"
                   "<p><strong>List of working attacks and payoads:</strong> <br>"+workingattacks+"<br></p>"
                   "<p><strong>Full raw output content:</strong> <br>"+ui->txt_output_sh1->toPlainText()+"<br></p>"
                   "</div><br><br><br>"
                   "<br><br><div><br><br><p style=\"font-size:100px\"><br><br>VAITP - Vulnerability Attack and Injection Tool in Python<br>Development: Frédéric Bogaerts<br>Colaboration: Anush Deokar<br>Supervising teachers: PhD. Naghmeh Navaki, PhD. José Fonseca<br>DEI - Universidade de Coimbra - Portugal</p></div>"

                   "<div style='text-align:center'>"
                   "<img src=':/lineicons-free-basic-3.0/uc.png'/>"
                   "</div><br>";
    QTextDocument doc;
    doc.setHtml(html);

    //set a virtual printer to save as pdf
    QPrinter printer(QPrinter::HighResolution);
    QString fileName = ui->txt_vaitp_log_path->text()+"/VAITP_EXPORT_LOG_"+now+".pdf";
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setPageSize(QPageSize::A4);
    printer.setPageMargins(QMarginsF(15,15,15,15));
    printer.setOutputFileName(fileName);

    //print
    doc.print(&printer);
    qDebug()<<"Extract report saved to "<<fileName;
    ui->txt_output_sh1->appendHtml("VAITP report created: "+fileName);
    qApp->processEvents();

    //open the file
    QDesktopServices::openUrl(QUrl::fromLocalFile(fileName));
}


void VAITP::on_actionQuit_triggered()
{
    QCoreApplication::quit();
}

