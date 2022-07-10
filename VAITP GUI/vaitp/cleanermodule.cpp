#include "cleanermodule.h"
#include <QDebug>
#include <QFile>
#include <QRegularExpression>

cleanermodule::cleanermodule()
{


    qDebug()<<"Cleaner module loaded";
}

/**
 * @brief cleanermodule::cleanFile
 * @param aFile file to be clean
 */

void cleanermodule::cleanFile(QString aFile){

    QString REGEX_PYTHON_SINGLELINE_COMMENT = "#(.)*"; // #
    QString REGEX_PYTHON_MULTILINE_COMMENT = "((''')|(\"\"\"))((.)|\n|\r)*((''')|(\"\"\"))"; // ''' or """


    QFile inputFile(aFile);
    QString fileContent="";
    if(inputFile.open(QIODevice::ReadOnly)){
        QTextStream in(&inputFile);
        fileContent = in.readAll();

    } else {
        qDebug()<<"File "<<aFile<<" was not cleaned due to error opening for reading.";
    }
    inputFile.close();
    if(inputFile.open(QIODevice::WriteOnly | QIODevice::Text)){
        QTextStream out(&inputFile);

        QRegularExpression re(REGEX_PYTHON_SINGLELINE_COMMENT);
        QRegularExpression re_ml(REGEX_PYTHON_MULTILINE_COMMENT);

        QString newfileContent = fileContent.replace(re,"").replace(re_ml,"");

        out<<newfileContent;
        out.flush();
    } else {
        qDebug()<<"File "<<aFile<<" was not cleaned due to error opening for writing.";
    }
    inputFile.close();

}


/**
 * @brief cleanermodule::comparetwofiles checks if two files have the same content (case insensitively)
 * @param aFile first file for comparison
 * @param bFile second file for comparison
 * @return boolean indicating if the files have the same content
 */

bool cleanermodule::comparetwofiles(QFile* aFile,QFile* bFile){

    if(!aFile->open(QIODevice::ReadOnly | QIODevice::Text)){
        qDebug()<< "Error opening aFile ";
        return false;
    }
    if(!bFile->open(QIODevice::ReadOnly | QIODevice::Text)){
        qDebug()<< "Error opening bFile ";
        return false;
    }

    QTextStream in1(aFile), in2(bFile);

    while(!in1.atEnd() && in2.atEnd()){
        QString linha_a = in1.readLine();
        QString linha_b = in2.readLine();
        if(QString::compare(linha_a,linha_b,Qt::CaseInsensitive) != 0){
            qDebug()<<"The files differ.";
            return false;
        }
    }


    return true;
}


void cleanermodule::forceDeOfuscation(QString aFile){
    //TODO: Implement force deobfuscation
}
