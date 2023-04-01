#include "log.h"

Log::Log(const int& n_chunks,
         QObject* parent)
    : QObject(parent),
    nChunks(n_chunks) {
    stopLoggingFlag = new bool(false);
}

Log::~Log(){
    delete stopLoggingFlag;
}

void Log::setFileAddress(QString addr) {
    FileAddress = addr;
}

void Log::setFlagData(bool *flg){
    flagData = flg;
}

void Log::setBuffer(uint8_t *buff){
    buffer = buff;
}

void Log::setChunkLen(const int& chunk_len){
    chunkLen = chunk_len;
}

void Log::stop(){
    *stopLoggingFlag = true;
}

void Log::log(){
    openFile();
    startLogging();
    closeFile();
    emit finished();
}

void Log::openFile(){
    QString strTime = QTime::currentTime().toString("hh-mm-ss");
    QString strDate = QDate::currentDate().toString("yy-MM-dd");
    QString strFilePath = FileAddress;

    strFilePath.append("log__");
    strFilePath.append(strDate);
    strFilePath.append("__");
    strFilePath.append(strTime);
    strFilePath.append(".bin");
    qDebug() << "logAddress = " << strFilePath;

    outputFile.open(strFilePath.toStdString(), std::ios::binary);
    if(!outputFile.is_open()){
        qDebug() << "Error: outputFile could not be opened";
        exit(0);
    }
}

void Log::startLogging() {
    *stopLoggingFlag = false;
    int cursor{};

    while(!(*stopLoggingFlag)){
        if (flagData[cursor]){
            outputFile.write(reinterpret_cast<const char*>(buffer + cursor*chunkLen), chunkLen * sizeof(uint8_t));
            flagData[cursor++] = false;
            if (cursor == nChunks) cursor = 0;
        }
    }
}

void Log::closeFile(){
    outputFile.close();
}


