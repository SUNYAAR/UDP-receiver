#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    updateParams();
    forceSetNetwork();

    connect(ui->CB_DevList, SIGNAL(currentIndexChanged(int)), this, SLOT(forceSetNetwork()));
    connect(ui->LE_PortNum, SIGNAL(textChanged(const QString&)), this, SLOT(forceSetNetwork()));
    connect(ui->LE_FrameLen, SIGNAL(textChanged(const QString&)), this, SLOT(forceSetNetwork()));
    connect(ui->LE_Fragment, SIGNAL(textChanged(const QString&)), this, SLOT(forceSetNetwork()));
    connect(ui->LE_Pattern, SIGNAL(textChanged(const QString&)), this, SLOT(forceSetNetwork()));
    connect(ui->LE_SrcIP, SIGNAL(textChanged(const QString&)), this, SLOT(forceSetNetwork()));

    qDebug()<<"Log:"<<chunkLen;
    logger = new Log(nChunks);
    loggerThread = new QThread;
    logger->moveToThread(loggerThread);
    loggerThread->start();
    qDebug()<<"receiver:"<<chunkLen;
    receiver = new PcapWrapper(sourceIP, nChunks);
    receiverThread = new QThread;
    receiver->moveToThread(receiverThread);
    receiverThread->start();

    ui->CB_DevList->addItems(receiver->deviceList());
    connect(ui->PB_SetNetwork, SIGNAL(clicked(bool)), this, SLOT(setNetwork()));
    connect(ui->PB_Start, SIGNAL(clicked(bool)), this, SLOT(start()));
    connect(logger, SIGNAL(finished()), this, SLOT(reset()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::forceSetNetwork(){
    networkInitialized = false;
    ui->PB_Start->setEnabled(false);
}

void MainWindow::enableConfigUI(bool enable){
    ui->CB_DevList->setEnabled(enable);
    ui->LE_PortNum->setEnabled(enable);
    ui->LE_SrcIP->setEnabled(enable);
    ui->PB_SetNetwork->setEnabled(enable);
    ui->LE_FrameLen->setEnabled(enable);
}

void MainWindow::setUpLoggerAndReceiver(){
    delete[] buffer;
    buffer = new uint8_t[nChunks * chunkLen];
    delete[] flagData;
    flagData = new bool[nChunks]{};

    logger->setChunkLen(chunkLen);
    logger->setBuffer(buffer);
    logger->setFlagData(flagData);
    logger->setFileAddress("");

    receiver->setChunkLen(chunkLen);
    receiver->setBuffer(buffer);
    receiver->setFlagData(flagData);
}

void MainWindow::setNetwork(){
    bool ok;
    const unsigned int parsedValue = ui->LE_Pattern->text().toUInt(&ok, 16);

    updateParams();

    receiver->setupRx(sourceIP, ui->CB_DevList->currentIndex()+1);
    receiver->setFilter(portNumber, frameLen,parsedValue,fragment);

    networkInitialized = true;
    ui->PB_Start->setEnabled(true);
}

void MainWindow::updateParams(){
    portNumber = ui->LE_PortNum->text().toInt();
    frameLen = ui->LE_FrameLen->text().toInt();
    fragment = ui->LE_Fragment->text().toUInt();
    chunkLen = frameLen * fragment;
    qDebug()<<"updateParams:"<<chunkLen<<fragment<<frameLen;
    sourceIP = QString::fromStdString(ui->LE_SrcIP->text().toStdString());
}

void MainWindow::start(){
    if (ui->PB_Start->text().toLower().contains("start")) {
        ui->PB_Start->setText("Stop");
        enableConfigUI(false);
        setUpLoggerAndReceiver();

        QTimer::singleShot(400, logger, SLOT(log()));
        QTimer::singleShot(500, receiver, SLOT(capture()));
    } else {
        logger->stop();
        receiver->stop();
        ui->PB_Start->setEnabled(false);
    }
}

void MainWindow::reset() {
    ui->PB_Start->setText("Start");
    ui->PB_Start->setEnabled(true);
    enableConfigUI(true);
}
