#include "vaitp.h"

#include <QApplication>
#include <QSplashScreen>
#include <QTimer>
#include <QLocale>
#include <QTranslator>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QPixmap pixmap(":/splash.png");
       QSplashScreen splash(pixmap, Qt::WindowStaysOnTopHint);
       splash.show();
       QTimer::singleShot(3000, &splash, &QWidget::close); // keep displayed for 5 seconds

    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "vaitp_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            a.installTranslator(&translator);
            break;
        }
    }


    VAITP w;
    w.show();
    return a.exec();
}
