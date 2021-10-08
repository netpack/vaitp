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
    int chainNum;
    void patchInjection(QString pyfile,bool isChained,QStringList patchList,bool isTemp);
    QStringList tempFiles;

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

private:
    Ui::VAITP *ui;
};
#endif // VAITP_H
