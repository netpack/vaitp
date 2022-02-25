#ifndef DETECTIONMODULE_H
#define DETECTIONMODULE_H

#include <QString>



class detectionModule
{
public:
    detectionModule();
    QStringList scanFileForVulnerabilities(QString aFile);
    QStringList scanFileForInjectionCalls(QString aFile);
};

#endif // DETECTIONMODULE_H
