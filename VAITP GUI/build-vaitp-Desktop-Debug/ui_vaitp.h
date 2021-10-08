/********************************************************************************
** Form generated from reading UI file 'vaitp.ui'
**
** Created by: Qt User Interface Compiler version 5.15.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_VAITP_H
#define UI_VAITP_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_VAITP
{
public:
    QAction *actionAbout;
    QAction *actionQuit;
    QAction *actionReScan_for_injected_files;
    QWidget *centralwidget;
    QLabel *lbl_info;
    QTabWidget *tabWidget;
    QWidget *tab;
    QLineEdit *txt_py_src;
    QToolButton *bt_load_py_src;
    QLabel *label;
    QPushButton *bt_scan_py;
    QPlainTextEdit *txt_output_sh1;
    QLabel *label_7;
    QPushButton *bt_export_output_sh1;
    QPushButton *bt_clearAll;
    QTabWidget *tabWidget_2;
    QWidget *tab_vulnerabilities;
    QListWidget *lst_vulns;
    QLabel *label_4;
    QLabel *label_2;
    QTextEdit *txt_vulnDescription;
    QPushButton *bt_autopown;
    QWidget *tab_injections;
    QLabel *label_3;
    QListWidget *lst_injectionPoints;
    QPushButton *bt_inject_vuln;
    QLabel *label_8;
    QListWidget *lst_injectedFiles;
    QLabel *label_5;
    QListWidget *lst_injectionsChain;
    QPushButton *bt_addToInjectionChain;
    QPushButton *bt_executeInjectionChain;
    QPushButton *bt_deleteInjectedFile;
    QPushButton *bt_setInjectedFileAsTarget;
    QPushButton *bt_clearInjectionChain;
    QWidget *tab_attack;
    QPushButton *bt_attack;
    QLabel *label_6;
    QListWidget *lst_payload;
    QLabel *label_9;
    QListWidget *lst_workingAttacks;
    QPushButton *bt_auto_daisyChain;
    QLabel *label_10;
    QPushButton *bt_exportReport;
    QLabel *lbl_target;
    QLabel *label_11;
    QLabel *label_12;
    QLineEdit *lineEdit;
    QLineEdit *lineEdit_2;
    QLineEdit *lineEdit_3;
    QLabel *label_13;
    QLabel *label_14;
    QPushButton *pushButton_2;
    QLabel *label_15;
    QLineEdit *lineEdit_4;
    QWidget *tab_2;
    QMenuBar *menubar;
    QMenu *menuFile;
    QMenu *menuAbout;
    QMenu *menuInjections;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *VAITP)
    {
        if (VAITP->objectName().isEmpty())
            VAITP->setObjectName(QString::fromUtf8("VAITP"));
        VAITP->resize(1320, 638);
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/logo/icon_48.png"), QSize(), QIcon::Normal, QIcon::Off);
        VAITP->setWindowIcon(icon);
        actionAbout = new QAction(VAITP);
        actionAbout->setObjectName(QString::fromUtf8("actionAbout"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/lineicons-free-basic-3.0/png-files/question-circle.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionAbout->setIcon(icon1);
        actionQuit = new QAction(VAITP);
        actionQuit->setObjectName(QString::fromUtf8("actionQuit"));
        actionReScan_for_injected_files = new QAction(VAITP);
        actionReScan_for_injected_files->setObjectName(QString::fromUtf8("actionReScan_for_injected_files"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/lineicons-free-basic-3.0/png-files/reload.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionReScan_for_injected_files->setIcon(icon2);
        centralwidget = new QWidget(VAITP);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        lbl_info = new QLabel(centralwidget);
        lbl_info->setObjectName(QString::fromUtf8("lbl_info"));
        lbl_info->setGeometry(QRect(30, 570, 851, 20));
        lbl_info->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);
        tabWidget = new QTabWidget(centralwidget);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        tabWidget->setGeometry(QRect(0, 0, 1311, 561));
        tabWidget->setIconSize(QSize(48, 48));
        tab = new QWidget();
        tab->setObjectName(QString::fromUtf8("tab"));
        txt_py_src = new QLineEdit(tab);
        txt_py_src->setObjectName(QString::fromUtf8("txt_py_src"));
        txt_py_src->setGeometry(QRect(140, 20, 511, 31));
        bt_load_py_src = new QToolButton(tab);
        bt_load_py_src->setObjectName(QString::fromUtf8("bt_load_py_src"));
        bt_load_py_src->setGeometry(QRect(660, 19, 41, 31));
        label = new QLabel(tab);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(10, 19, 141, 31));
        bt_scan_py = new QPushButton(tab);
        bt_scan_py->setObjectName(QString::fromUtf8("bt_scan_py"));
        bt_scan_py->setGeometry(QRect(720, 20, 181, 31));
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/lineicons-free-basic-3.0/png-files/magnifier.png"), QSize(), QIcon::Normal, QIcon::Off);
        bt_scan_py->setIcon(icon3);
        txt_output_sh1 = new QPlainTextEdit(tab);
        txt_output_sh1->setObjectName(QString::fromUtf8("txt_output_sh1"));
        txt_output_sh1->setGeometry(QRect(10, 380, 1291, 101));
        label_7 = new QLabel(tab);
        label_7->setObjectName(QString::fromUtf8("label_7"));
        label_7->setGeometry(QRect(10, 360, 131, 18));
        bt_export_output_sh1 = new QPushButton(tab);
        bt_export_output_sh1->setObjectName(QString::fromUtf8("bt_export_output_sh1"));
        bt_export_output_sh1->setEnabled(false);
        bt_export_output_sh1->setGeometry(QRect(1140, 490, 161, 31));
        bt_clearAll = new QPushButton(tab);
        bt_clearAll->setObjectName(QString::fromUtf8("bt_clearAll"));
        bt_clearAll->setGeometry(QRect(970, 490, 161, 31));
        tabWidget_2 = new QTabWidget(tab);
        tabWidget_2->setObjectName(QString::fromUtf8("tabWidget_2"));
        tabWidget_2->setGeometry(QRect(6, 70, 1291, 281));
        tab_vulnerabilities = new QWidget();
        tab_vulnerabilities->setObjectName(QString::fromUtf8("tab_vulnerabilities"));
        lst_vulns = new QListWidget(tab_vulnerabilities);
        lst_vulns->setObjectName(QString::fromUtf8("lst_vulns"));
        lst_vulns->setGeometry(QRect(10, 30, 351, 141));
        label_4 = new QLabel(tab_vulnerabilities);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        label_4->setGeometry(QRect(10, 10, 261, 20));
        label_2 = new QLabel(tab_vulnerabilities);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setGeometry(QRect(370, 10, 101, 18));
        txt_vulnDescription = new QTextEdit(tab_vulnerabilities);
        txt_vulnDescription->setObjectName(QString::fromUtf8("txt_vulnDescription"));
        txt_vulnDescription->setGeometry(QRect(370, 30, 881, 141));
        txt_vulnDescription->setAutoFillBackground(false);
        txt_vulnDescription->setInputMethodHints(Qt::ImhMultiLine|Qt::ImhNoEditMenu);
        txt_vulnDescription->setReadOnly(true);
        bt_autopown = new QPushButton(tab_vulnerabilities);
        bt_autopown->setObjectName(QString::fromUtf8("bt_autopown"));
        bt_autopown->setEnabled(false);
        bt_autopown->setGeometry(QRect(160, 180, 201, 31));
        tabWidget_2->addTab(tab_vulnerabilities, QString());
        tab_injections = new QWidget();
        tab_injections->setObjectName(QString::fromUtf8("tab_injections"));
        label_3 = new QLabel(tab_injections);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        label_3->setGeometry(QRect(10, 10, 271, 18));
        lst_injectionPoints = new QListWidget(tab_injections);
        lst_injectionPoints->setObjectName(QString::fromUtf8("lst_injectionPoints"));
        lst_injectionPoints->setGeometry(QRect(10, 30, 351, 141));
        bt_inject_vuln = new QPushButton(tab_injections);
        bt_inject_vuln->setObjectName(QString::fromUtf8("bt_inject_vuln"));
        bt_inject_vuln->setEnabled(false);
        bt_inject_vuln->setGeometry(QRect(10, 180, 171, 31));
        label_8 = new QLabel(tab_injections);
        label_8->setObjectName(QString::fromUtf8("label_8"));
        label_8->setGeometry(QRect(730, 10, 141, 18));
        lst_injectedFiles = new QListWidget(tab_injections);
        lst_injectedFiles->setObjectName(QString::fromUtf8("lst_injectedFiles"));
        lst_injectedFiles->setGeometry(QRect(730, 30, 341, 141));
        label_5 = new QLabel(tab_injections);
        label_5->setObjectName(QString::fromUtf8("label_5"));
        label_5->setGeometry(QRect(370, 10, 161, 18));
        lst_injectionsChain = new QListWidget(tab_injections);
        lst_injectionsChain->setObjectName(QString::fromUtf8("lst_injectionsChain"));
        lst_injectionsChain->setGeometry(QRect(370, 30, 351, 141));
        bt_addToInjectionChain = new QPushButton(tab_injections);
        bt_addToInjectionChain->setObjectName(QString::fromUtf8("bt_addToInjectionChain"));
        bt_addToInjectionChain->setEnabled(false);
        bt_addToInjectionChain->setGeometry(QRect(190, 180, 171, 31));
        bt_executeInjectionChain = new QPushButton(tab_injections);
        bt_executeInjectionChain->setObjectName(QString::fromUtf8("bt_executeInjectionChain"));
        bt_executeInjectionChain->setEnabled(false);
        bt_executeInjectionChain->setGeometry(QRect(370, 180, 171, 31));
        bt_deleteInjectedFile = new QPushButton(tab_injections);
        bt_deleteInjectedFile->setObjectName(QString::fromUtf8("bt_deleteInjectedFile"));
        bt_deleteInjectedFile->setEnabled(false);
        bt_deleteInjectedFile->setGeometry(QRect(730, 180, 161, 31));
        bt_setInjectedFileAsTarget = new QPushButton(tab_injections);
        bt_setInjectedFileAsTarget->setObjectName(QString::fromUtf8("bt_setInjectedFileAsTarget"));
        bt_setInjectedFileAsTarget->setEnabled(false);
        bt_setInjectedFileAsTarget->setGeometry(QRect(900, 180, 171, 31));
        bt_clearInjectionChain = new QPushButton(tab_injections);
        bt_clearInjectionChain->setObjectName(QString::fromUtf8("bt_clearInjectionChain"));
        bt_clearInjectionChain->setGeometry(QRect(550, 180, 171, 31));
        tabWidget_2->addTab(tab_injections, QString());
        tab_attack = new QWidget();
        tab_attack->setObjectName(QString::fromUtf8("tab_attack"));
        bt_attack = new QPushButton(tab_attack);
        bt_attack->setObjectName(QString::fromUtf8("bt_attack"));
        bt_attack->setEnabled(false);
        bt_attack->setGeometry(QRect(10, 210, 171, 31));
        label_6 = new QLabel(tab_attack);
        label_6->setObjectName(QString::fromUtf8("label_6"));
        label_6->setGeometry(QRect(10, 40, 131, 18));
        lst_payload = new QListWidget(tab_attack);
        lst_payload->setObjectName(QString::fromUtf8("lst_payload"));
        lst_payload->setGeometry(QRect(10, 60, 351, 141));
        label_9 = new QLabel(tab_attack);
        label_9->setObjectName(QString::fromUtf8("label_9"));
        label_9->setGeometry(QRect(700, 40, 121, 18));
        lst_workingAttacks = new QListWidget(tab_attack);
        lst_workingAttacks->setObjectName(QString::fromUtf8("lst_workingAttacks"));
        lst_workingAttacks->setGeometry(QRect(700, 60, 331, 141));
        bt_auto_daisyChain = new QPushButton(tab_attack);
        bt_auto_daisyChain->setObjectName(QString::fromUtf8("bt_auto_daisyChain"));
        bt_auto_daisyChain->setEnabled(false);
        bt_auto_daisyChain->setGeometry(QRect(190, 210, 171, 31));
        bt_auto_daisyChain->setIconSize(QSize(24, 24));
        label_10 = new QLabel(tab_attack);
        label_10->setObjectName(QString::fromUtf8("label_10"));
        label_10->setGeometry(QRect(10, 10, 91, 31));
        bt_exportReport = new QPushButton(tab_attack);
        bt_exportReport->setObjectName(QString::fromUtf8("bt_exportReport"));
        bt_exportReport->setEnabled(false);
        bt_exportReport->setGeometry(QRect(869, 210, 161, 31));
        lbl_target = new QLabel(tab_attack);
        lbl_target->setObjectName(QString::fromUtf8("lbl_target"));
        lbl_target->setGeometry(QRect(100, 10, 1181, 31));
        label_11 = new QLabel(tab_attack);
        label_11->setObjectName(QString::fromUtf8("label_11"));
        label_11->setGeometry(QRect(370, 40, 71, 20));
        label_12 = new QLabel(tab_attack);
        label_12->setObjectName(QString::fromUtf8("label_12"));
        label_12->setGeometry(QRect(370, 100, 131, 31));
        label_12->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        lineEdit = new QLineEdit(tab_attack);
        lineEdit->setObjectName(QString::fromUtf8("lineEdit"));
        lineEdit->setEnabled(false);
        lineEdit->setGeometry(QRect(510, 100, 171, 31));
        lineEdit_2 = new QLineEdit(tab_attack);
        lineEdit_2->setObjectName(QString::fromUtf8("lineEdit_2"));
        lineEdit_2->setEnabled(false);
        lineEdit_2->setGeometry(QRect(510, 60, 171, 31));
        lineEdit_3 = new QLineEdit(tab_attack);
        lineEdit_3->setObjectName(QString::fromUtf8("lineEdit_3"));
        lineEdit_3->setEnabled(false);
        lineEdit_3->setGeometry(QRect(510, 140, 171, 31));
        label_13 = new QLabel(tab_attack);
        label_13->setObjectName(QString::fromUtf8("label_13"));
        label_13->setGeometry(QRect(370, 67, 131, 21));
        label_13->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        label_14 = new QLabel(tab_attack);
        label_14->setObjectName(QString::fromUtf8("label_14"));
        label_14->setGeometry(QRect(370, 147, 131, 21));
        label_14->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        pushButton_2 = new QPushButton(tab_attack);
        pushButton_2->setObjectName(QString::fromUtf8("pushButton_2"));
        pushButton_2->setEnabled(false);
        pushButton_2->setGeometry(QRect(510, 210, 171, 31));
        label_15 = new QLabel(tab_attack);
        label_15->setObjectName(QString::fromUtf8("label_15"));
        label_15->setGeometry(QRect(370, 190, 131, 21));
        label_15->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);
        lineEdit_4 = new QLineEdit(tab_attack);
        lineEdit_4->setObjectName(QString::fromUtf8("lineEdit_4"));
        lineEdit_4->setEnabled(false);
        lineEdit_4->setGeometry(QRect(510, 180, 171, 26));
        tabWidget_2->addTab(tab_attack, QString());
        tabWidget->addTab(tab, QString());
        tab_2 = new QWidget();
        tab_2->setObjectName(QString::fromUtf8("tab_2"));
        tabWidget->addTab(tab_2, QString());
        VAITP->setCentralWidget(centralwidget);
        menubar = new QMenuBar(VAITP);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 1320, 23));
        menuFile = new QMenu(menubar);
        menuFile->setObjectName(QString::fromUtf8("menuFile"));
        QIcon icon4;
        icon4.addFile(QString::fromUtf8(":/logo/icon_24.png"), QSize(), QIcon::Normal, QIcon::Off);
        menuFile->setIcon(icon4);
        menuAbout = new QMenu(menubar);
        menuAbout->setObjectName(QString::fromUtf8("menuAbout"));
        menuAbout->setIcon(icon1);
        menuInjections = new QMenu(menubar);
        menuInjections->setObjectName(QString::fromUtf8("menuInjections"));
        QIcon icon5;
        icon5.addFile(QString::fromUtf8(":/lineicons-free-basic-3.0/png-files/syringe.png"), QSize(), QIcon::Normal, QIcon::Off);
        menuInjections->setIcon(icon5);
        VAITP->setMenuBar(menubar);
        statusbar = new QStatusBar(VAITP);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        VAITP->setStatusBar(statusbar);

        menubar->addAction(menuFile->menuAction());
        menubar->addAction(menuInjections->menuAction());
        menubar->addAction(menuAbout->menuAction());
        menuFile->addAction(actionQuit);
        menuAbout->addAction(actionAbout);
        menuInjections->addAction(actionReScan_for_injected_files);

        retranslateUi(VAITP);

        tabWidget->setCurrentIndex(0);
        tabWidget_2->setCurrentIndex(1);


        QMetaObject::connectSlotsByName(VAITP);
    } // setupUi

    void retranslateUi(QMainWindow *VAITP)
    {
        VAITP->setWindowTitle(QCoreApplication::translate("VAITP", "VAITP", nullptr));
        actionAbout->setText(QCoreApplication::translate("VAITP", "About", nullptr));
        actionQuit->setText(QCoreApplication::translate("VAITP", "Quit", nullptr));
        actionReScan_for_injected_files->setText(QCoreApplication::translate("VAITP", "ReScan for injected files", nullptr));
#if QT_CONFIG(tooltip)
        lbl_info->setToolTip(QString());
#endif // QT_CONFIG(tooltip)
        lbl_info->setText(QCoreApplication::translate("VAITP", "VAITP - Vulnerability Attack and Injection Tool for Python v0.1 Beta", nullptr));
        bt_load_py_src->setText(QCoreApplication::translate("VAITP", "...", nullptr));
        label->setText(QCoreApplication::translate("VAITP", "Select a Python file:", nullptr));
        bt_scan_py->setText(QCoreApplication::translate("VAITP", "Scan File", nullptr));
        label_7->setText(QCoreApplication::translate("VAITP", "Output:", nullptr));
        bt_export_output_sh1->setText(QCoreApplication::translate("VAITP", "Export output", nullptr));
        bt_clearAll->setText(QCoreApplication::translate("VAITP", "Clear all", nullptr));
        label_4->setText(QCoreApplication::translate("VAITP", "Vulnerabilities:", nullptr));
        label_2->setText(QCoreApplication::translate("VAITP", "Description:", nullptr));
        bt_autopown->setText(QCoreApplication::translate("VAITP", "Auto POWN", nullptr));
        tabWidget_2->setTabText(tabWidget_2->indexOf(tab_vulnerabilities), QCoreApplication::translate("VAITP", "Vulnerabilities", nullptr));
        label_3->setText(QCoreApplication::translate("VAITP", "Injection points:", nullptr));
        bt_inject_vuln->setText(QCoreApplication::translate("VAITP", "Inject single Vulnerability", nullptr));
        label_8->setText(QCoreApplication::translate("VAITP", "Injected files:", nullptr));
        label_5->setText(QCoreApplication::translate("VAITP", "Chain of injection points:", nullptr));
        bt_addToInjectionChain->setText(QCoreApplication::translate("VAITP", "Add to injection chain", nullptr));
        bt_executeInjectionChain->setText(QCoreApplication::translate("VAITP", "Execute injection chain", nullptr));
        bt_deleteInjectedFile->setText(QCoreApplication::translate("VAITP", "Delete injected file", nullptr));
        bt_setInjectedFileAsTarget->setText(QCoreApplication::translate("VAITP", "Set as target", nullptr));
        bt_clearInjectionChain->setText(QCoreApplication::translate("VAITP", "Clear injection chain", nullptr));
        tabWidget_2->setTabText(tabWidget_2->indexOf(tab_injections), QCoreApplication::translate("VAITP", "Injections", nullptr));
        bt_attack->setText(QCoreApplication::translate("VAITP", "Single Attack", nullptr));
        label_6->setText(QCoreApplication::translate("VAITP", "Attack payloads:", nullptr));
        label_9->setText(QCoreApplication::translate("VAITP", "Working attacks:", nullptr));
        bt_auto_daisyChain->setText(QCoreApplication::translate("VAITP", "Auto Daisy-Chain Attacks", nullptr));
        label_10->setText(QCoreApplication::translate("VAITP", "Attack target: ", nullptr));
        bt_exportReport->setText(QCoreApplication::translate("VAITP", "Export Report", nullptr));
        lbl_target->setText(QCoreApplication::translate("VAITP", "No target selected.", nullptr));
        label_11->setText(QCoreApplication::translate("VAITP", "Fuzzer:", nullptr));
        label_12->setText(QCoreApplication::translate("VAITP", "Main chars:", nullptr));
        lineEdit->setText(QCoreApplication::translate("VAITP", ";ls", nullptr));
        lineEdit_2->setText(QCoreApplication::translate("VAITP", "'\"'`", nullptr));
        lineEdit_3->setText(QCoreApplication::translate("VAITP", "'\"'`", nullptr));
        label_13->setText(QCoreApplication::translate("VAITP", "Prep chars:", nullptr));
        label_14->setText(QCoreApplication::translate("VAITP", "End chars:", nullptr));
        pushButton_2->setText(QCoreApplication::translate("VAITP", "Payload Fuzz!", nullptr));
        label_15->setText(QCoreApplication::translate("VAITP", "Expected output:", nullptr));
        lineEdit_4->setText(QCoreApplication::translate("VAITP", "/", nullptr));
        tabWidget_2->setTabText(tabWidget_2->indexOf(tab_attack), QCoreApplication::translate("VAITP", "Attacks", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab), QCoreApplication::translate("VAITP", "Local", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_2), QCoreApplication::translate("VAITP", "Remote", nullptr));
        menuFile->setTitle(QCoreApplication::translate("VAITP", "VAITP", nullptr));
        menuAbout->setTitle(QCoreApplication::translate("VAITP", "Help", nullptr));
        menuInjections->setTitle(QCoreApplication::translate("VAITP", "Injections", nullptr));
    } // retranslateUi

};

namespace Ui {
    class VAITP: public Ui_VAITP {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_VAITP_H
