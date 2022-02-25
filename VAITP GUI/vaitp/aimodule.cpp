#include "aimodule.h"

#include <QDebug>
#include <QDir>
#include <QFile>
#include <QProcess>
#include <QRegularExpression>
#include <QSqlQuery>


aimodule::aimodule()
{
    qDebug()<<"AI module loaded";
}

int aimodule::cvefixes_count_vulns()
{
    QSqlQuery sql_query;
    QString sql_count = "SELECT count(*) FROM method_change m , file_change f WHERE f.file_change_id = m.file_change_id AND f.programming_language = 'Python' AND m.before_change = 'True'";
    int num_python_vulns = 0;
    if(sql_query.exec(sql_count)){
        sql_query.next();
        num_python_vulns = sql_query.value(0).toInt();
    }
    return num_python_vulns;
}


int aimodule::cvefixes_count_patches()
{
    QSqlQuery sql_query;
    QString sql_count = "SELECT count(*) FROM method_change m , file_change f WHERE f.file_change_id = m.file_change_id AND f.programming_language = 'Python' AND m.before_change = 'False'";
    int num_python_patches = 0;
    if(sql_query.exec(sql_count)){
        sql_query.next();
        num_python_patches = sql_query.value(0).toInt();
    }
    return num_python_patches;
}


void aimodule::opencvefixesdb(){
    //Open the db
    if(!cvefixesdb.isOpen()){
        qDebug()<<"Opening CVEfixes db...";
        cvefixesdb=QSqlDatabase::addDatabase("QSQLITE");
        cvefixesdb.setDatabaseName("../vaitp/CVEfixes.db");
        cvefixesdb.open();
    }
}

void aimodule::rm_old_ai_vulns(QString path_vuln)
{
    QDir dir(path_vuln);
    dir.setNameFilters(QStringList() << "*.txt");
    dir.setFilter(QDir::Files);
    foreach(QString dirFile, dir.entryList())
    {
        dir.remove(dirFile);
    }
}

void aimodule::rm_old_dataset(){
    //rm tests
    QString path_vuln = "../vaitp/vaitp_dataset/test/vulnerable/";
    QString path_nonvuln = "../vaitp/vaitp_dataset/test/nonvulnerable/";
    rm_old_ai_vulns(path_vuln);
    rm_old_ai_vulns(path_nonvuln);

    //rm trains
    path_vuln = "../vaitp/vaitp_dataset/train/vulnerable/";
    path_nonvuln = "../vaitp/vaitp_dataset/train/nonvulnerable/";
    rm_old_ai_vulns(path_vuln);
    rm_old_ai_vulns(path_nonvuln);
}

QStringList aimodule::get_dataset_first_half(int aNumHalfDataset){
    QSqlQuery sql_query;
    QStringList processedVulns;

    //get half of the vulnerabilities for training (and leave the other half for testing)
    sql_query.prepare("SELECT m.name, m.signature, m.nloc, m.parameters, m.token_count, m.code FROM method_change m , file_change f "
                      "WHERE f.file_change_id = m.file_change_id "
                      "AND f.programming_language = 'Python' "
                      "AND m.before_change = 'True' "
                      "LIMIT 0, :halfthedatafortraining");

    sql_query.bindValue(":halfthedatafortraining", aNumHalfDataset);

    qDebug()<< "num vulns for trainig :: "<<aNumHalfDataset;

    int num_of_processed_vulns = 0;
    if(sql_query.exec()){
        while(sql_query.next()){

            QString txt_name = sql_query.value(0).toString();
            QString txt_sig = sql_query.value(1).toString();
            QString txt_nloc = sql_query.value(2).toString();
            QString txt_params = sql_query.value(3).toString();
            QString txt_tokencount = sql_query.value(4).toString();
            QString txt_code = sql_query.value(5).toString();

            //qDebug()<<"\n NAME: "<<txt_name<<"\n SIGNATURE: "<<txt_sig<<"\n NLOC: "<<txt_nloc<<"\n PARAMS: "<<txt_params<<"\n TOKEN COUNT: "<<txt_tokencount<<"\n CODE: "<<txt_code;
            qDebug()<<"Processing vulnerability for training: "<<txt_name;
            processedVulns.append(txt_name);

            QString filename = QString("../vaitp/vaitp_dataset/train/vulnerable/%1.txt").arg(num_of_processed_vulns);
            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
                return processedVulns;

            QTextStream out(&file);
            out << "\""<<txt_code<<"\"";

            file.flush();
            file.close();

            num_of_processed_vulns++;


        }
   } else {
        qDebug()<<"Unable to execute SQL query";
    }

    qDebug()<<"All vulnerabilities were exported for training.";
    return processedVulns;

}




QStringList aimodule::get_dataset_first_half_patches(int aNumHalfDataset){
    QSqlQuery sql_query;
    QStringList processedVulns;

    //get half of the patches for training (and leave the other half for testing)
    sql_query.prepare("SELECT m.name, m.signature, m.nloc, m.parameters, m.token_count, m.code FROM method_change m , file_change f "
                      "WHERE f.file_change_id = m.file_change_id "
                      "AND f.programming_language = 'Python' "
                      "AND m.before_change = 'False' "
                      "LIMIT 0, :halfthedatafortraining");

    sql_query.bindValue(":halfthedatafortraining", aNumHalfDataset);

    qDebug()<< "num patches for trainig :: "<<aNumHalfDataset;

    int num_of_processed = 0;
    if(sql_query.exec()){
        while(sql_query.next()){

            QString txt_name = sql_query.value(0).toString();
            QString txt_sig = sql_query.value(1).toString();
            QString txt_nloc = sql_query.value(2).toString();
            QString txt_params = sql_query.value(3).toString();
            QString txt_tokencount = sql_query.value(4).toString();
            QString txt_code = sql_query.value(5).toString();

            //qDebug()<<"\n NAME: "<<txt_name<<"\n SIGNATURE: "<<txt_sig<<"\n NLOC: "<<txt_nloc<<"\n PARAMS: "<<txt_params<<"\n TOKEN COUNT: "<<txt_tokencount<<"\n CODE: "<<txt_code;
            qDebug()<<"Processing patch for training: "<<txt_name;
            processedVulns.append(txt_name);

            QString filename = QString("../vaitp/vaitp_dataset/train/nonvulnerable/%1.txt").arg(num_of_processed);
            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
                return processedVulns;

            QTextStream out(&file);
            out << "\""<<txt_code<<"\"";

            file.flush();
            file.close();

            num_of_processed++;


        }
   } else {
        qDebug()<<"Unable to execute SQL query";
    }

    qDebug()<<"All patches were exported for training.";
    return processedVulns;

}




QStringList aimodule::get_dataset_second_half(int aNumHalfDataset){

    QSqlQuery sql_query;
    QStringList processedVulns;

    //get half of the vulnerabilities for testing
    sql_query.prepare("SELECT m.name, m.signature, m.nloc, m.parameters, m.token_count, m.code FROM method_change m , file_change f "
                      "WHERE f.file_change_id = m.file_change_id "
                      "AND f.programming_language = 'Python' "
                      "AND m.before_change = 'True' "
                      "LIMIT :halfthedatafortraining, -1");

    sql_query.bindValue(":halfthedatafortraining", aNumHalfDataset);

    qDebug()<< "num vulns for testing :: "<<aNumHalfDataset;

    int num_of_processed_vulns = 0;
    if(sql_query.exec()){
        while(sql_query.next()){

            QString txt_name = sql_query.value(0).toString();
            QString txt_sig = sql_query.value(1).toString();
            QString txt_nloc = sql_query.value(2).toString();
            QString txt_params = sql_query.value(3).toString();
            QString txt_tokencount = sql_query.value(4).toString();
            QString txt_code = sql_query.value(5).toString();

            //qDebug()<<"\n NAME: "<<txt_name<<"\n SIGNATURE: "<<txt_sig<<"\n NLOC: "<<txt_nloc<<"\n PARAMS: "<<txt_params<<"\n TOKEN COUNT: "<<txt_tokencount<<"\n CODE: "<<txt_code;
            qDebug()<<"Processing vulnerability for testing: "<<txt_name;
            processedVulns.append(txt_name);

            QString filename = QString("../vaitp/vaitp_dataset/test/vulnerable/%1.txt").arg(num_of_processed_vulns);
            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
                return processedVulns;

            QTextStream out(&file);
            out << "\""<<txt_code.replace("\n","")<<"\"";

            file.flush();
            file.close();

            num_of_processed_vulns++;

        }



    } else {
        qDebug()<<"Unable to execute SQL query";
    }




    qDebug()<<"All vulnerabilities were exported for testing.";

    return processedVulns;

}



QStringList aimodule::get_dataset_second_half_patches(int aNumHalfDataset){

    QSqlQuery sql_query;
    QStringList processedVulns;

    //get half of the vulnerabilities for testing
    sql_query.prepare("SELECT m.name, m.signature, m.nloc, m.parameters, m.token_count, m.code FROM method_change m , file_change f "
                      "WHERE f.file_change_id = m.file_change_id "
                      "AND f.programming_language = 'Python' "
                      "AND m.before_change = 'False' "
                      "LIMIT :halfthedatafortraining, -1");

    sql_query.bindValue(":halfthedatafortraining", aNumHalfDataset);

    qDebug()<< "num patches for testing :: "<<aNumHalfDataset;

    int num_of_processed = 0;
    if(sql_query.exec()){
        while(sql_query.next()){

            QString txt_name = sql_query.value(0).toString();
            QString txt_sig = sql_query.value(1).toString();
            QString txt_nloc = sql_query.value(2).toString();
            QString txt_params = sql_query.value(3).toString();
            QString txt_tokencount = sql_query.value(4).toString();
            QString txt_code = sql_query.value(5).toString();

            //qDebug()<<"\n NAME: "<<txt_name<<"\n SIGNATURE: "<<txt_sig<<"\n NLOC: "<<txt_nloc<<"\n PARAMS: "<<txt_params<<"\n TOKEN COUNT: "<<txt_tokencount<<"\n CODE: "<<txt_code;
            qDebug()<<"Processing patch for testing: "<<txt_name;
            processedVulns.append(txt_name);

            QString filename = QString("../vaitp/vaitp_dataset/test/nonvulnerable/%1.txt").arg(num_of_processed);
            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
                return processedVulns;

            QTextStream out(&file);
            out << "\""<<txt_code.replace("\n","")<<"\"";

            file.flush();
            file.close();

            num_of_processed++;

        }



    } else {
        qDebug()<<"Unable to execute SQL query";
    }




    qDebug()<<"All patches were exported for testing.";

    return processedVulns;

}

void aimodule::trainModule(){
   /* QProcess p;
    QStringList params;

    params << "../vaitp/trainmodel_textClassificationRNNs_vaitp.py";
    p.start("python", params);
    p.waitForFinished(-1);
    QString p_stdout = p.readAll();*/

}
