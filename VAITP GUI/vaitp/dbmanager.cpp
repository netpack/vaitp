#include "dbmanager.h"
#include <QDebug>

DbManager::DbManager(const QString& path)
{
   adb = QSqlDatabase::addDatabase("QSQLITE");
   adb.setDatabaseName(path);

   if (!m_db.open())
   {
      qDebug() << "Error: connection with database failed";
   }
   else
   {
      qDebug() << "Database: connection ok";
   }
}
