#ifndef PCAPWRAPPER_H
#define PCAPWRAPPER_H

#include <QObject>
#include <QtCore>
#include <QMutex>
#include "winpcap.h"


class PcapWrapper : public QObject
{
    Q_OBJECT
public:
    explicit PcapWrapper(const QString& host_address,
                         const int& n_chunks,
                         QObject *parent = 0);
    int setupRx(const QString& host_address, const int& idev);
    void setFilter(const uint16_t& port, const uint16_t& frameLen, const uint16_t &pattern, const uint16_t &fragment);

    void setBuffer(uint8_t *);
    void setFlagData(bool *);
    void setChunkLen(const int& chunk_len);
    void stop();

    WinPcap *mPcap;
    int counter{0};
public slots:
    int capture();
    QStringList deviceList();

private:
    uint8_t *buffer;
    bool *flagData;
    const int nChunks;
    int chunkLen;

    bool *flagStopThread;
};

#endif // PCAPWRAPPER_H
