/****************************************************************************
** Meta object code from reading C++ file 'vaitp.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../vaitp/vaitp.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'vaitp.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_VAITP_t {
    QByteArrayData data[13];
    char stringdata0[260];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_VAITP_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_VAITP_t qt_meta_stringdata_VAITP = {
    {
QT_MOC_LITERAL(0, 0, 5), // "VAITP"
QT_MOC_LITERAL(1, 6, 25), // "on_bt_load_py_src_clicked"
QT_MOC_LITERAL(2, 32, 0), // ""
QT_MOC_LITERAL(3, 33, 21), // "on_bt_scan_py_clicked"
QT_MOC_LITERAL(4, 55, 25), // "on_bt_inject_vuln_clicked"
QT_MOC_LITERAL(5, 81, 25), // "on_bt_restore_pys_clicked"
QT_MOC_LITERAL(6, 107, 34), // "on_lst_injectionPoints_itemCl..."
QT_MOC_LITERAL(7, 142, 16), // "QListWidgetItem*"
QT_MOC_LITERAL(8, 159, 4), // "item"
QT_MOC_LITERAL(9, 164, 24), // "on_lst_vulns_itemClicked"
QT_MOC_LITERAL(10, 189, 20), // "on_bt_attack_clicked"
QT_MOC_LITERAL(11, 210, 22), // "on_bt_clearAll_clicked"
QT_MOC_LITERAL(12, 233, 26) // "on_lst_payload_itemClicked"

    },
    "VAITP\0on_bt_load_py_src_clicked\0\0"
    "on_bt_scan_py_clicked\0on_bt_inject_vuln_clicked\0"
    "on_bt_restore_pys_clicked\0"
    "on_lst_injectionPoints_itemClicked\0"
    "QListWidgetItem*\0item\0on_lst_vulns_itemClicked\0"
    "on_bt_attack_clicked\0on_bt_clearAll_clicked\0"
    "on_lst_payload_itemClicked"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_VAITP[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       9,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   59,    2, 0x08 /* Private */,
       3,    0,   60,    2, 0x08 /* Private */,
       4,    0,   61,    2, 0x08 /* Private */,
       5,    0,   62,    2, 0x08 /* Private */,
       6,    1,   63,    2, 0x08 /* Private */,
       9,    1,   66,    2, 0x08 /* Private */,
      10,    0,   69,    2, 0x08 /* Private */,
      11,    0,   70,    2, 0x08 /* Private */,
      12,    1,   71,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 7,    8,
    QMetaType::Void, 0x80000000 | 7,    8,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 7,    8,

       0        // eod
};

void VAITP::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<VAITP *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->on_bt_load_py_src_clicked(); break;
        case 1: _t->on_bt_scan_py_clicked(); break;
        case 2: _t->on_bt_inject_vuln_clicked(); break;
        case 3: _t->on_bt_restore_pys_clicked(); break;
        case 4: _t->on_lst_injectionPoints_itemClicked((*reinterpret_cast< QListWidgetItem*(*)>(_a[1]))); break;
        case 5: _t->on_lst_vulns_itemClicked((*reinterpret_cast< QListWidgetItem*(*)>(_a[1]))); break;
        case 6: _t->on_bt_attack_clicked(); break;
        case 7: _t->on_bt_clearAll_clicked(); break;
        case 8: _t->on_lst_payload_itemClicked((*reinterpret_cast< QListWidgetItem*(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject VAITP::staticMetaObject = { {
    QMetaObject::SuperData::link<QMainWindow::staticMetaObject>(),
    qt_meta_stringdata_VAITP.data,
    qt_meta_data_VAITP,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *VAITP::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *VAITP::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_VAITP.stringdata0))
        return static_cast<void*>(this);
    return QMainWindow::qt_metacast(_clname);
}

int VAITP::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 9)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 9;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 9)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 9;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
