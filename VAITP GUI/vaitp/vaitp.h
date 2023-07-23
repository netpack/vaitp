#ifndef VAITP_H
#define VAITP_H

#include <QtSql>
#include <QMainWindow>
#include <QListWidgetItem>

QT_BEGIN_NAMESPACE
namespace Ui { class VAITP; }
QT_END_NAMESPACE

class VAITP : public QMainWindow
{
    Q_OBJECT

public:
    VAITP(QWidget *parent = nullptr);
    ~VAITP();
    QSqlDatabase db;
    QSqlDatabase cvefixesdb;
    int chainNum;
    void patchInjection(QString pyfile,bool isChained,QStringList patchList,bool isTemp);
    QStringList tempFiles;
    int cvefixes_count_vulns();
    void rm_old_ai_vulns(QString path_vuln);
    void vaitp_scan_py_file(QString aFile);
    void typeNextCharacter();
    void animateTyping(QString aString);
private slots:
    void on_bt_load_py_src_clicked();
    void on_bt_scan_py_clicked();
    void on_bt_inject_vuln_clicked();
    void on_lst_injectionPoints_itemClicked(QListWidgetItem *item);
    void on_lst_vulns_itemClicked(QListWidgetItem *item);
    void on_bt_attack_clicked();
    void on_bt_clearAll_clicked();
    void on_lst_payload_itemClicked(QListWidgetItem *item);
    void on_lst_injectedFiles_itemClicked(QListWidgetItem *item);
    void on_actionReScan_for_injected_files_triggered();
    void on_bt_addToInjectionChain_clicked();
    void on_bt_executeInjectionChain_clicked();
    void on_bt_clearInjectionChain_clicked();
    void on_bt_extract_cvefixes_vulns_clicked();
    void on_bt_ai_extract_cvef_diffs_clicked();
    void on_bt_extract_common_words_clicked();
    void on_bt_load_ai_models_path_clicked();
    void on_checkBox_use_vaitp_ai_classificator_stateChanged(int arg1);
    void on_bt_extract_one_line_clicked();
    void on_checkBox_use_vaitp_ai_s2s_stateChanged(int arg1);
    void on_bt_load_log_output_path_clicked();
    void on_comboBox_vaitp_ai_classificator_currentIndexChanged(int index);
    void on_bt_setInjectedFileAsTarget_clicked();
    void on_checkBox_change_dir_on_attack_stateChanged(int arg1);
    void on_actionImport_payloads_to_vaitp_db_triggered();
    void on_actionClear_all_outputs_and_lists_triggered();
    void on_bt_load_py_src_folder_clicked();
    void on_bt_scan_py_folder_clicked();
    void on_actionAbout_triggered();
    void on_actionExport_PDF_report_triggered();
    void on_actionQuit_triggered();

private:
    Ui::VAITP *ui;
};
#endif // VAITP_H
