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
#include <QtWidgets/QToolButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_VAITP
{
public:
    QAction *actionAbout;
    QAction *actionQuit;
    QWidget *centralwidget;
    QLabel *lbl_info;
    QTabWidget *tabWidget;
    QWidget *tab;
    QLineEdit *txt_py_src;
    QToolButton *bt_load_py_src;
    QLabel *label;
    QListWidget *lst_injectionPoints;
    QLabel *label_4;
    QListWidget *lst_vulns;
    QLabel *label_3;
    QPushButton *bt_scan_py;
    QPushButton *bt_inject_vuln;
    QPushButton *bt_restore_pys;
    QPushButton *bt_attack;
    QLabel *label_6;
    QPlainTextEdit *txt_output_sh1;
    QLabel *label_7;
    QPushButton *bt_export_output_sh1;
    QListWidget *lst_payload;
    QPushButton *bt_clearAll;
    QListWidget *lst_injectedFiles;
    QLabel *label_8;
    QPushButton *bt_auto_daisyChain;
    QLabel *label_9;
    QListWidget *lst_workingAttacks;
    QWidget *tab_2;
    QMenuBar *menubar;
    QMenu *menuFile;
    QMenu *menuAbout;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *VAITP)
    {
        if (VAITP->objectName().isEmpty())
            VAITP->setObjectName(QString::fromUtf8("VAITP"));
        VAITP->resize(1435, 656);
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/logo/icon_48.png"), QSize(), QIcon::Normal, QIcon::Off);
        VAITP->setWindowIcon(icon);
        actionAbout = new QAction(VAITP);
        actionAbout->setObjectName(QString::fromUtf8("actionAbout"));
        actionQuit = new QAction(VAITP);
        actionQuit->setObjectName(QString::fromUtf8("actionQuit"));
        centralwidget = new QWidget(VAITP);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        lbl_info = new QLabel(centralwidget);
        lbl_info->setObjectName(QString::fromUtf8("lbl_info"));
        lbl_info->setGeometry(QRect(0, 570, 851, 20));
        lbl_info->setAlignment(Qt::AlignLeading|Qt::AlignLeft|Qt::AlignVCenter);
        tabWidget = new QTabWidget(centralwidget);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        tabWidget->setGeometry(QRect(0, 0, 1421, 561));
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
        label->setGeometry(QRect(10, 30, 141, 20));
        lst_injectionPoints = new QListWidget(tab);
        lst_injectionPoints->setObjectName(QString::fromUtf8("lst_injectionPoints"));
        lst_injectionPoints->setGeometry(QRect(360, 100, 341, 141));
        label_4 = new QLabel(tab);
        label_4->setObjectName(QString::fromUtf8("label_4"));
        label_4->setGeometry(QRect(10, 80, 261, 20));
        lst_vulns = new QListWidget(tab);
        lst_vulns->setObjectName(QString::fromUtf8("lst_vulns"));
        lst_vulns->setGeometry(QRect(10, 100, 341, 141));
        label_3 = new QLabel(tab);
        label_3->setObjectName(QString::fromUtf8("label_3"));
        label_3->setGeometry(QRect(360, 80, 271, 18));
        bt_scan_py = new QPushButton(tab);
        bt_scan_py->setObjectName(QString::fromUtf8("bt_scan_py"));
        bt_scan_py->setGeometry(QRect(720, 20, 151, 31));
        bt_inject_vuln = new QPushButton(tab);
        bt_inject_vuln->setObjectName(QString::fromUtf8("bt_inject_vuln"));
        bt_inject_vuln->setEnabled(false);
        bt_inject_vuln->setGeometry(QRect(360, 250, 341, 31));
        bt_restore_pys = new QPushButton(tab);
        bt_restore_pys->setObjectName(QString::fromUtf8("bt_restore_pys"));
        bt_restore_pys->setEnabled(true);
        bt_restore_pys->setGeometry(QRect(10, 440, 341, 31));
        bt_attack = new QPushButton(tab);
        bt_attack->setObjectName(QString::fromUtf8("bt_attack"));
        bt_attack->setEnabled(false);
        bt_attack->setGeometry(QRect(710, 250, 341, 31));
        label_6 = new QLabel(tab);
        label_6->setObjectName(QString::fromUtf8("label_6"));
        label_6->setGeometry(QRect(710, 80, 131, 18));
        txt_output_sh1 = new QPlainTextEdit(tab);
        txt_output_sh1->setObjectName(QString::fromUtf8("txt_output_sh1"));
        txt_output_sh1->setGeometry(QRect(360, 320, 1041, 151));
        label_7 = new QLabel(tab);
        label_7->setObjectName(QString::fromUtf8("label_7"));
        label_7->setGeometry(QRect(360, 300, 131, 18));
        bt_export_output_sh1 = new QPushButton(tab);
        bt_export_output_sh1->setObjectName(QString::fromUtf8("bt_export_output_sh1"));
        bt_export_output_sh1->setEnabled(false);
        bt_export_output_sh1->setGeometry(QRect(1240, 480, 161, 31));
        lst_payload = new QListWidget(tab);
        lst_payload->setObjectName(QString::fromUtf8("lst_payload"));
        lst_payload->setGeometry(QRect(710, 100, 341, 141));
        bt_clearAll = new QPushButton(tab);
        bt_clearAll->setObjectName(QString::fromUtf8("bt_clearAll"));
        bt_clearAll->setGeometry(QRect(1050, 480, 161, 31));
        lst_injectedFiles = new QListWidget(tab);
        lst_injectedFiles->setObjectName(QString::fromUtf8("lst_injectedFiles"));
        lst_injectedFiles->setGeometry(QRect(10, 320, 341, 111));
        label_8 = new QLabel(tab);
        label_8->setObjectName(QString::fromUtf8("label_8"));
        label_8->setGeometry(QRect(10, 300, 141, 18));
        bt_auto_daisyChain = new QPushButton(tab);
        bt_auto_daisyChain->setObjectName(QString::fromUtf8("bt_auto_daisyChain"));
        bt_auto_daisyChain->setEnabled(false);
        bt_auto_daisyChain->setGeometry(QRect(1140, 20, 261, 31));
        bt_auto_daisyChain->setIconSize(QSize(24, 24));
        label_9 = new QLabel(tab);
        label_9->setObjectName(QString::fromUtf8("label_9"));
        label_9->setGeometry(QRect(1060, 80, 121, 18));
        lst_workingAttacks = new QListWidget(tab);
        lst_workingAttacks->setObjectName(QString::fromUtf8("lst_workingAttacks"));
        lst_workingAttacks->setGeometry(QRect(1060, 100, 341, 141));
        tabWidget->addTab(tab, QString());
        tab_2 = new QWidget();
        tab_2->setObjectName(QString::fromUtf8("tab_2"));
        tabWidget->addTab(tab_2, QString());
        VAITP->setCentralWidget(centralwidget);
        menubar = new QMenuBar(VAITP);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 1435, 23));
        menuFile = new QMenu(menubar);
        menuFile->setObjectName(QString::fromUtf8("menuFile"));
        menuAbout = new QMenu(menubar);
        menuAbout->setObjectName(QString::fromUtf8("menuAbout"));
        VAITP->setMenuBar(menubar);
        statusbar = new QStatusBar(VAITP);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        VAITP->setStatusBar(statusbar);

        menubar->addAction(menuFile->menuAction());
        menubar->addAction(menuAbout->menuAction());
        menuFile->addAction(actionQuit);
        menuAbout->addAction(actionAbout);

        retranslateUi(VAITP);

        tabWidget->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(VAITP);
    } // setupUi

    void retranslateUi(QMainWindow *VAITP)
    {
        VAITP->setWindowTitle(QCoreApplication::translate("VAITP", "VAITP", nullptr));
        actionAbout->setText(QCoreApplication::translate("VAITP", "About", nullptr));
        actionQuit->setText(QCoreApplication::translate("VAITP", "Quit", nullptr));
#if QT_CONFIG(tooltip)
        lbl_info->setToolTip(QString());
#endif // QT_CONFIG(tooltip)
        lbl_info->setText(QCoreApplication::translate("VAITP", "VAITP - Vulnerability Attack and Injection Tool for Python v0.1 Beta", nullptr));
        bt_load_py_src->setText(QCoreApplication::translate("VAITP", "...", nullptr));
        label->setText(QCoreApplication::translate("VAITP", "Select a Python file:", nullptr));
        label_4->setText(QCoreApplication::translate("VAITP", "Vulnerabilities:", nullptr));
        label_3->setText(QCoreApplication::translate("VAITP", "Injection points:", nullptr));
        bt_scan_py->setText(QCoreApplication::translate("VAITP", "Scan File", nullptr));
        bt_inject_vuln->setText(QCoreApplication::translate("VAITP", "Inject Vulnerability", nullptr));
        bt_restore_pys->setText(QCoreApplication::translate("VAITP", "Restore un-injected files", nullptr));
        bt_attack->setText(QCoreApplication::translate("VAITP", "Single Attack", nullptr));
        label_6->setText(QCoreApplication::translate("VAITP", "Attack payloads:", nullptr));
        label_7->setText(QCoreApplication::translate("VAITP", "Output:", nullptr));
        bt_export_output_sh1->setText(QCoreApplication::translate("VAITP", "Export output", nullptr));
        bt_clearAll->setText(QCoreApplication::translate("VAITP", "Clear all", nullptr));
        label_8->setText(QCoreApplication::translate("VAITP", "Injected files:", nullptr));
        bt_auto_daisyChain->setText(QCoreApplication::translate("VAITP", "Auto Daisy-Chain Attack", nullptr));
        label_9->setText(QCoreApplication::translate("VAITP", "Working attacks:", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab), QCoreApplication::translate("VAITP", "Local", nullptr));
        tabWidget->setTabText(tabWidget->indexOf(tab_2), QCoreApplication::translate("VAITP", "Remote", nullptr));
        menuFile->setTitle(QCoreApplication::translate("VAITP", "VAITP", nullptr));
        menuAbout->setTitle(QCoreApplication::translate("VAITP", "Help", nullptr));
    } // retranslateUi

};

namespace Ui {
    class VAITP: public Ui_VAITP {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_VAITP_H
