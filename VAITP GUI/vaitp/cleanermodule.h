#ifndef CLEANERMODULE_H
#define CLEANERMODULE_H

#include <QFile>



class cleanermodule
{
public:
    cleanermodule();
    bool comparetwofiles(QFile *aFile, QFile *bFile);
    void cleanFile(QString file);
    void forceDeOfuscation(QString aFile);
};

#endif // CLEANERMODULE_H
