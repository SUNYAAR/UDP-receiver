#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>

#include "pcapwrapper.h"
#include "log.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;

    int frameLen;
    int fragment;
    int chunkLen; //check these two with winpcap filters (dirty, I know)
    const int nChunks{50};

    bool networkInitialized{false};
    int portNumber;
    QString sourceIP;
    Log *logger;
    PcapWrapper *receiver;
    QThread *loggerThread, *receiverThread;

    uint8_t *buffer = nullptr;
    bool *flagData = nullptr;
    void setUpLoggerAndReceiver();
    void enableConfigUI(bool enable);
    void updateParams();

private slots:
    void forceSetNetwork();
    void setNetwork();
    void start();
    void reset();

};
#endif // MAINWINDOW_H
