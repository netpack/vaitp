#include "aimodule.h"
#include "cleanermodule.h"

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

int aimodule::cvefixes_count_diffs()
{
    QSqlQuery sql_query;
    //only count when there are less than 10 lines changed
    QString sql_count = "SELECT count(*) FROM file_change f WHERE f.programming_language = 'Python' AND f.num_lines_added < 10 AND f.num_lines_deleted < 10";
    int num_python_diff = 0;
    if(sql_query.exec(sql_count)){
        sql_query.next();
        num_python_diff = sql_query.value(0).toInt();
    }
    return num_python_diff;
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

void aimodule::rm_temp(){
    //rm temps
    QString path_vuln = "../vaitp/vaitp_dataset/temp/vulnerable/";
    QString path_nonvuln = "../vaitp/vaitp_dataset/temp/nonvulnerable/";
    rm_old_ai_vulns(path_vuln);
    rm_old_ai_vulns(path_nonvuln);
}

void aimodule::rm_temp_diffs(){
    //rm temps
    QString path_vuln = "../vaitp/vaitp_dataset_diffs/temp/vulnerable/";
    QString path_nonvuln = "../vaitp/vaitp_dataset_diffs/temp/nonvulnerable/";
    rm_old_ai_vulns(path_vuln);
    rm_old_ai_vulns(path_nonvuln);
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

    //get part of the vulnerabilities for training (and leave the other half for testing)

    /* sql_query.prepare("SELECT m.name, m.signature, m.nloc, m.parameters, m.token_count, m.code, c.num_lines_added, c.num_lines_deleted "
                      "FROM method_change m , file_change f, commits c "
                      "WHERE f.file_change_id = m.file_change_id "
                      "AND f.programming_language = 'Python' "
                      "AND m.before_change = 'True' "
                      "AND c.hash = f.hash "
                      "AND c.num_lines_added < 2"
                      "AND c.num_lines_deleted < 2"
                      "LIMIT 0, :halfthedatafortraining"); */

    sql_query.prepare("SELECT m.name, m.signature, m.nloc, m.parameters, m.token_count, m.code "
                      "FROM method_change m , file_change f "
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
            //out << "\""<<txt_code<<"\"";
            out << txt_code;

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
            //out << "\""<<txt_code<<"\"";
            out << txt_code;

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


QStringList aimodule::getAndProcess_dataset_vulnerabilities(){
    QSqlQuery sql_query;
    QStringList processedVulns;
    cleanermodule clnr;
    //get the dataset
    sql_query.prepare("SELECT m.name, m.signature, m.nloc, m.parameters, m.token_count, m.code FROM method_change m , file_change f "
                      "WHERE f.file_change_id = m.file_change_id "
                      "AND f.programming_language = 'Python' "
                      "AND m.before_change = 'True'");

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
            qDebug()<<"Processing vulnerablility: "<<txt_name;
            processedVulns.append(txt_name);

            QString filename = QString("../vaitp/vaitp_dataset/temp/vulnerable/%1.txt").arg(num_of_processed);
            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
                return processedVulns;

            QTextStream out(&file);
            //out << "\""<<txt_code<<"\"";
            out << txt_code;

            file.flush();
            file.close();

            /**
             * @brief clnr
             * send it to the cleaner mode to clean junk
             */

            clnr.cleanFile(filename);


            num_of_processed++;


        }
   } else {
        qDebug()<<"Unable to execute SQL query";
    }

    qDebug()<<"All vulnerabilities were exported.";
    return processedVulns;

}


QStringList aimodule::getAndProcess_dataset_patches(){
    QSqlQuery sql_query;
    QStringList processedVulns;
    cleanermodule clnr;

    //get the dataset
    sql_query.prepare("SELECT m.name, m.signature, m.nloc, m.parameters, m.token_count, m.code FROM method_change m , file_change f "
                      "WHERE f.file_change_id = m.file_change_id "
                      "AND f.programming_language = 'Python' "
                      "AND m.before_change = 'False'");

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
            qDebug()<<"Processing patch: "<<txt_name;
            processedVulns.append(txt_name);

            QString filename = QString("../vaitp/vaitp_dataset/temp/nonvulnerable/%1.txt").arg(num_of_processed);
            QFile file(filename);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
                return processedVulns;

            QTextStream out(&file);
            //out << "\""<<txt_code<<"\"";
            out << txt_code;

            file.flush();
            file.close();

            /**
             * @brief clnr
             * send it to the cleaner mode to clean junk
             */
            clnr.cleanFile(filename);


            num_of_processed++;


        }
   } else {
        qDebug()<<"Unable to execute SQL query";
    }

    qDebug()<<"All patches were exported.";
    return processedVulns;

}



QStringList aimodule::getAndProcess_dataset_diffs(){
    QSqlQuery sql_query;
    QStringList processedVulns;
    cleanermodule clnr;
    //get the dataset
    sql_query.prepare("SELECT diff_parsed, file_change_id FROM file_change f "
                      "WHERE f.programming_language = 'Python'  and change_type = \"ModificationType.MODIFY\""
                      );

    int num_of_processed = 0;
    if(sql_query.exec()){
        while(sql_query.next()){

            QString txt_diff = sql_query.value(0).toString();
            QString txt_file_change_id = sql_query.value(1).toString();

            qDebug()<<"Processing diff: "<<txt_diff;

            QStringList process_diff = txt_diff.split("'deleted':");


            QRegularExpression r("{'added':\\s\\[\\("); //limpar inicio
            QString linesadded = process_diff[0].replace(r,"");
            qDebug()<<"[ADD] start trimmed :: "<<linesadded;


            QRegularExpression re("('|\")\\)\\],"); //limpar final
            linesadded.replace(re,"");
            qDebug()<<"[ADD] end trimmed :: "<<linesadded;


            /**
             * Extract and filter added lines
             */
            QRegularExpression ree("('|\")\\), \\("); //split entries
            QStringList linesadded_splitted = linesadded.split(ree);

            QStringList filterWords = {"try:","pass","except ImportError:"}; //filter out all of these
            QStringList filterContains = {"__version__","release","VERSION","endif","<td"}; //filter out all that contain these (somewhere in the line)
            QStringList validLines;
            int numlines = linesadded_splitted.count();
            for(int nl=0; nl<numlines; nl++){
                QRegularExpression rextract("\\d+,\\s('|\")");
                QString extractedLine = linesadded_splitted[nl].replace(rextract,"").replace(QRegularExpression("from\\s+[\\w+\\.\\w+]+[\\s+import\\s+\\w*]"),""); //don't add imports
                if(!extractedLine.trimmed().isEmpty()){
                    if(extractedLine.trimmed().at(0) != "#"){ //filter out comments


                        bool hasMatched = false;

                        /*for(const auto& word : filterWords){
                            if(QString::compare(extractedLine,word) == 0)
                                hasMatched = true;
                        }
                        for(const auto& word : filterContains){
                            if(extractedLine.contains(word) == 0)
                                hasMatched = true;
                        }*/
                        if(!hasMatched && extractedLine.size() < 10000) //filter out huge lines
                            validLines.append(extractedLine.trimmed().replace(QRegularExpression("#.*"),"").trimmed().replace(QRegularExpression("('|\")\\), ('|\")"),"\n").replace(QRegularExpression("((''')|(\"\"\"))(.*(\\n|\\r)*)*((''')|(\"\"\"))"),"")); //limpa comentários no fim da linha + fix extraction errors + multiline comments
                    }
                }

            }


            for(const auto& linha : validLines){
                qDebug()<<"[ADD] Temos a linha :: "<<linha;
            }





            QRegularExpression r2("\\(\\d*,\\s");
            QRegularExpression r2e("'\\)\\]}");
            QRegularExpression r2s("\\['\\s*");
            QString linesdel = process_diff[1].replace(r2,"").replace(r2e,"").replace(r2s,"");


            /**
             * Extract and filter deleted lines
             */
            QStringList linesdel_splitted = linesdel.split(ree);


            QStringList validLinesDel;
            int numlinesdel = linesdel_splitted.count();
            for(int nl=0; nl<numlinesdel; nl++){
                QRegularExpression rextract("\\d+,\\s('|\")");
                QString extractedLine = linesdel_splitted[nl].replace(rextract,"").replace(QRegularExpression("from\\s+[\\w+\\.\\w+]+[\\s+import\\s+\\w*]"),""); //don't add imports
                if(!extractedLine.trimmed().isEmpty()){
                    if(extractedLine.trimmed().at(0) != "#"){ //filter out comments

                        bool hasMatched = false;
                        /*for(const auto& word : filterWords){
                            if(QString::compare(extractedLine,word) == 0)
                                hasMatched = true;
                        }
                        for(const auto& word : filterContains){
                            if(extractedLine.contains(word) == 0)
                                hasMatched = true;
                        }*/
                        if(!hasMatched && extractedLine.size() < 10000) //filter out huge lines and versions
                            validLinesDel.append(extractedLine.trimmed().replace(QRegularExpression("#.*"),"").trimmed().replace(QRegularExpression("('|\")\\), ('|\")"),"\n").replace(QRegularExpression("((''')|(\"\"\"))(.*(\\n|\\r)*)*((''')|(\"\"\"))"),"")); //limpa comentários no fim da linha + fix extraction errors + multiline comments
                    }
                }

            }


            for(const auto& linha : validLinesDel){
                qDebug()<<"[DEL] Temos a linha :: "<<linha;
            }





            processedVulns.append("\n@@ ++ "+linesadded+" ++ @@ @@ -- "+linesdel+" -- @@");


            /**
             * Write patch files
             */

            //int nl = 0;
            QString filename_patch = QString("../vaitp/vaitp_dataset_diffs/temp/nonvulnerable/%1_%2.txt").arg(num_of_processed).arg(txt_file_change_id);
            QFile file_patch(filename_patch);
            if (!file_patch.open((QIODevice::WriteOnly | QIODevice::Text)))
                return processedVulns;
            QTextStream out_patch(&file_patch);

            for(const auto& linhaAdded : validLines){
                out_patch << linhaAdded << "\n";

            }

            file_patch.flush();
            file_patch.close();
            //nl++;
            qDebug()<<"File created (patch): "<<filename_patch;


            /**
             * Write vulnerable files
             */

            //nl = 0;
            QString filename_vuln = QString("../vaitp/vaitp_dataset_diffs/temp/vulnerable/%1_%2.txt").arg(num_of_processed).arg(txt_file_change_id);
            QFile file_vuln(filename_vuln);
            if (!file_vuln.open((QIODevice::WriteOnly | QIODevice::Text)))
                return processedVulns;

            QTextStream out_vuln(&file_vuln);
            for(const auto& linhaDel : validLinesDel){
                out_vuln << linhaDel << "\n";

            }
            file_vuln.flush();
            file_vuln.close();
            //nl++;
            qDebug()<<"File created (vulnerability): "<<filename_vuln;

            num_of_processed++;


        }
   } else {
        qDebug()<<"Unable to execute SQL query";
    }

    qDebug()<<"All vulnerabilities were exported.";

    qDebug()<<"Deleting duplicates...";
    /*delete duplicates*/
    QProcess process;
    process.start("fdupes", QStringList() << "-rdN" << "/home/fred/msi/ano2/VAITP/VAITP GUI/vaitp/vaitp_dataset_diffs/temp/");
    process.waitForFinished(60000);


    return processedVulns;

}


