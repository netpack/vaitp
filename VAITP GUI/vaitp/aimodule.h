#ifndef AIMODULE_H
#define AIMODULE_H

#include <QSqlDatabase>
#include <QString>



class aimodule
{
public:
    aimodule();
    void rm_old_dataset();
    void rm_old_ai_vulns(QString path_vuln);
    void opencvefixesdb();
    QSqlDatabase cvefixesdb;
    int cvefixes_count_vulns();
    QStringList get_dataset_first_half(int aNumHalfDataset);
    QStringList get_dataset_second_half(int aNumHalfDataset);
    int cvefixes_count_patches();
    QStringList get_dataset_first_half_patches(int aNumHalfDataset);
    QStringList get_dataset_second_half_patches(int aNumHalfDataset);
    void trainModule();
    QStringList getAndProcess_dataset_vulnerabilities();
    QStringList getAndProcess_dataset_patches();
    void rm_temp();
    void rm_temp_diffs();
    int cvefixes_count_diffs();
    int cvefixes_count_entries();
    QStringList getAndProcess_dataset_diffs();
    void set_file_to_scan(QString aFile);
    QString run_classificator_model();
    QStringList getAndProcess_dataset_commonwords();
    int cvefixes_count_oneline_diffs();
    QStringList getAndProcess_dataset_oneline_diffs();
};

#endif // AIMODULE_H
