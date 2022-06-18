#include "detectionmodule.h"

#include <QDebug>
#include <QFile>
#include <QRegularExpression>
#include <QSqlQuery>

detectionModule::detectionModule()
{
    qDebug()<<"Detection module loaded";
}

QStringList detectionModule::scanFileForVulnerabilities(QString aFile){
    QStringList detectedVulnerabilities;
    QFile inputFile(aFile);
    QString sql_qry_vulns = "Select vulnerability from vulnerabilities";
    QSqlQuery sql;
    int line_num=0;

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
                      detectedVulnerabilities.append(vuln);
                  }
               }
            }
            inputFile.close();
        }
    }

    return detectedVulnerabilities;
}

QStringList detectionModule::scanFileForInjectionCalls(QString aFile){
    QStringList detectedCalls;
    QFile inputFile(aFile);
    QString sql_qry_patches = "Select patch_start, patch, patch_end, injection from injections";
    QSqlQuery sql;
    int line_num=0;

    if (inputFile.open(QIODevice::ReadOnly)){

        QTextStream in(&inputFile);
        while (!in.atEnd()){

            //if we can read the file and while were not at the end of it we get the next line
            QString line = in.readLine();
            line_num++;

            if(!line.isEmpty()){




                if(sql.exec(sql_qry_patches)){
                    while(sql.next()){
                        QString patch_start = sql.value(0).toString();
                        QString patch = sql.value(1).toString();
                        QString patch_end = sql.value(2).toString();
                        QString injection = sql.value(3).toString();
                        qDebug() << "Scanning line " << line_num << ": " << line << " for patch: " << patch_start<<patch<<patch_end;
                        qDebug() << "Injection is set to: "<<injection;

                        //Create regex
                        QRegularExpression re(patch_start+patch+patch_end);

                        QRegularExpressionMatch match = re.match(line);
                        if(match.hasMatch()){
                            // add patch to patch list
                            qDebug()<<"(0.0)  Patch regex matches: "+match.captured(0);

                            QString item;
                            //if(injection=="\\w+"){
                                qDebug()<<"(0.0) Injection is regex \\w+";
                                //item = match.captured(0)+" :: "+match.captured(0).remove(QRegularExpression(patch_start)).remove(QRegularExpression(patch_end)) + " :: Line " + QString::number(line_num) + ": "+line.trimmed();
                                item = match.captured(0)+" :: "+match.captured(0).remove(QRegularExpression(patch_start)).remove(QRegularExpression(patch_end)).replace(match.captured(0),injection) + " :: Line " + QString::number(line_num) + ": "+line.trimmed();
                            //} else {
                            //    qDebug()<<"(0.0) Injection is hard coded";
                             //   item = patch_start+patch+patch_end+" :: "+injection + " :: Line " + QString::number(line_num) + ": "+line.trimmed();

                           // }

                            qDebug()<<item;
                            detectedCalls.append(item);


                        }





                    }
                }





            }





            inputFile.close();
        }
    }

    return detectedCalls;
}
