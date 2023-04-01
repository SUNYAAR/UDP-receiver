#ifndef Log_H
#define Log_H

#include <QObject>
#include<QTimer>
#include<QDebug>
#include <QDate>
#include <QTime>

#include<fstream>
#include<chrono>

class Log : public QObject
{
    Q_OBJECT
public:
    explicit Log(const int& n_chunks,
                 QObject *parent = nullptr);
    ~Log();

    void setFileAddress(QString);
    void setFlagData(bool *);
    void setBuffer(uint8_t *);
    void setChunkLen(const int& chunk_len);
    void stop();

public slots:
    void log();

private:
    const int nChunks;
    int chunkLen;

    QString FileAddress;
    std::ofstream outputFile;
    bool *stopLoggingFlag;

    uint8_t *buffer;
    bool *flagData;

    void openFile();
    void startLogging();
    void closeFile();

signals:
    void finished();

};

#endif // Log_H
