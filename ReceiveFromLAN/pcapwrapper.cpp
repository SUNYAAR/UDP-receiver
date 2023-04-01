#include "pcapwrapper.h"

PcapWrapper::PcapWrapper(const QString& host_address,
                         const int& n_chunks,
                         QObject *parent)
    : QObject(parent)
    , nChunks(n_chunks)
{
    mPcap = new WinPcap(host_address);
    flagStopThread = new bool(false);
}

QStringList PcapWrapper::deviceList()
{
    QList<QString> devList;
    QList<QString> desc;
    mPcap->deviceChoice(devList,desc);

    QStringList outputList;
    int idxFirst;
    int idxLast;

    for(int i=0;i<devList.size();i++)
    {
        idxFirst = desc[i].indexOf("'")+1;
        idxLast = desc[i].lastIndexOf("'");
        outputList << desc[i].mid(idxFirst,idxLast-idxFirst);
    }

    return outputList;
}

int PcapWrapper::setupRx(const QString& host_address, const int& idev)
{
    qDebug() << "PcapWrapper::setupRx, idev = " << idev;
    int errCode;
    mPcap->setSourceIP(host_address);
    errCode = mPcap->setupRx(idev);
    return errCode;
}

void PcapWrapper::setFilter(const uint16_t& port, const uint16_t& frameLen, const uint16_t& pattern,const uint16_t& fragment)
{
    qDebug()<<"Pattern: "<<pattern;
    mPcap->setFilter(port, frameLen,pattern,fragment);
    counter=0;
}

void PcapWrapper::setBuffer(uint8_t *buff){
    buffer = buff;
}

void PcapWrapper::setChunkLen(const int& chunk_len){
    chunkLen = chunk_len;
}

void PcapWrapper::setFlagData(bool *flg){
    flagData = flg;
}

int PcapWrapper::capture()
{
    mPcap->resetFilterParams();
    *flagStopThread = false;

    qDebug() << "Capturing Thread ID:" << QThread::currentThreadId();

    int res;
    int size;
    uchar *data;
    int type;
    int freqIdx;

    int cursor{};

    //assumption: size = chunkLen = dt.len * dt.nfrags
    while((res = mPcap->next((void **)&data,size,type,freqIdx)) >= 0 && !(*flagStopThread))
    {
        if(type == 1){
            if(!flagData[cursor]){
                qDebug()<<counter++<<cursor*chunkLen;
                memcpy(buffer + cursor*chunkLen, data, size * sizeof(uint8_t));
                flagData[cursor++] = true;
                if(cursor == nChunks) cursor = 0;
            }
            else{
                qDebug() << "!! ---------------- Frame Loss, flagWr = " << cursor << " ------------------ !!";
            }

        }
    }

    if(res<0)
        qDebug() << "PcapWrapper: Packet Capturing Error: res=" << res;

    return res;
}

void PcapWrapper::stop()
{
    *flagStopThread = true;
    qDebug()<<"Capture Stoped";
}

