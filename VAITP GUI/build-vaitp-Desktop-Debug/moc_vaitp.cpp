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
    QByteArrayData data[17];
    char stringdata0[416];
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
QT_MOC_LITERAL(5, 81, 34), // "on_lst_injectionPoints_itemCl..."
QT_MOC_LITERAL(6, 116, 16), // "QListWidgetItem*"
QT_MOC_LITERAL(7, 133, 4), // "item"
QT_MOC_LITERAL(8, 138, 24), // "on_lst_vulns_itemClicked"
QT_MOC_LITERAL(9, 163, 20), // "on_bt_attack_clicked"
QT_MOC_LITERAL(10, 184, 22), // "on_bt_clearAll_clicked"
QT_MOC_LITERAL(11, 207, 26), // "on_lst_payload_itemClicked"
QT_MOC_LITERAL(12, 234, 32), // "on_lst_injectedFiles_itemClicked"
QT_MOC_LITERAL(13, 267, 44), // "on_actionReScan_for_injected_..."
QT_MOC_LITERAL(14, 312, 33), // "on_bt_addToInjectionChain_cli..."
QT_MOC_LITERAL(15, 346, 35), // "on_bt_executeInjectionChain_c..."
QT_MOC_LITERAL(16, 382, 33) // "on_bt_clearInjectionChain_cli..."

    },
    "VAITP\0on_bt_load_py_src_clicked\0\0"
    "on_bt_scan_py_clicked\0on_bt_inject_vuln_clicked\0"
    "on_lst_injectionPoints_itemClicked\0"
    "QListWidgetItem*\0item\0on_lst_vulns_itemClicked\0"
    "on_bt_attack_clicked\0on_bt_clearAll_clicked\0"
    "on_lst_payload_itemClicked\0"
    "on_lst_injectedFiles_itemClicked\0"
    "on_actionReScan_for_injected_files_triggered\0"
    "on_bt_addToInjectionChain_clicked\0"
    "on_bt_executeInjectionChain_clicked\0"
    "on_bt_clearInjectionChain_clicked"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_VAITP[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      13,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   79,    2, 0x08 /* Private */,
       3,    0,   80,    2, 0x08 /* Private */,
       4,    0,   81,    2, 0x08 /* Private */,
       5,    1,   82,    2, 0x08 /* Private */,
       8,    1,   85,    2, 0x08 /* Private */,
       9,    0,   88,    2, 0x08 /* Private */,
      10,    0,   89,    2, 0x08 /* Private */,
      11,    1,   90,    2, 0x08 /* Private */,
      12,    1,   93,    2, 0x08 /* Private */,
      13,    0,   96,    2, 0x08 /* Private */,
      14,    0,   97,    2, 0x08 /* Private */,
      15,    0,   98,    2, 0x08 /* Private */,
      16,    0,   99,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

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
        case 3: _t->on_lst_injectionPoints_itemClicked((*reinterpret_cast< QListWidgetItem*(*)>(_a[1]))); break;
        case 4: _t->on_lst_vulns_itemClicked((*reinterpret_cast< QListWidgetItem*(*)>(_a[1]))); break;
        case 5: _t->on_bt_attack_clicked(); break;
        case 6: _t->on_bt_clearAll_clicked(); break;
        case 7: _t->on_lst_payload_itemClicked((*reinterpret_cast< QListWidgetItem*(*)>(_a[1]))); break;
        case 8: _t->on_lst_injectedFiles_itemClicked((*reinterpret_cast< QListWidgetItem*(*)>(_a[1]))); break;
        case 9: _t->on_actionReScan_for_injected_files_triggered(); break;
        case 10: _t->on_bt_addToInjectionChain_clicked(); break;
        case 11: _t->on_bt_executeInjectionChain_clicked(); break;
        case 12: _t->on_bt_clearInjectionChain_clicked(); break;
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
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 13)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 13;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
