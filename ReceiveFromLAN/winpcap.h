#ifndef WINPCAP_H
#define WINPCAP_H


#include <QObject>


////#include "winsock2.h"
//#define WIN32_LEAN_AND_MEAN
//#define _WINSOCKAPI_
//#include "windows.h"

//#include "pcap.h"
//#include <QDebug>
//#include <QMutex>
//#include <QThread>
//#include <QFile>
//#include <QTime>
//#include <QDir>
//#include <QSemaphore>

#include <QObject>
#include "winsock2.h"
#include "windows.h"
#include "pcap.h"
#include <QDebug>
#include <QMutex>
#include <QThread>
#include <QFile>
#include <QTime>
#include <QDir>
#include <QSemaphore>

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

struct FrameType{
    u_int pattern;
    u_short len;
    u_short port;
    u_short nfrags;
    u_short fragLen;
    u_char *array = nullptr;
    int blockSize;
};

/* UDP header*/
struct UdpHeader{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
};

class WinPcap : public QObject
{
    Q_OBJECT
public:
    explicit WinPcap(const QString& host_address, QObject *parent = 0);

    void deviceChoice(QList<QString> &devNameList, QList<QString> &devDescList);
    void setFilter(const uint16_t& port, const uint16_t& frameLen, const uint16_t &patternSync, const uint16_t &fragment);
    int next(void **data, int &size, int &type, int &freqIdx);
    int setupRx(int iDev);
    void setSourceIP(const QString& host_address);
    void resetFilterParams();

private:
    QList<QString> devNameList;
    QList<QString> devDescList;
    QString hostAddress;

    int i;
    int res;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adHandle;
    pcap_if_t *alldevs;
    pcap_if_t *d;

    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    u_int netmask;
    ushort* fragNow = nullptr;
    ushort* fragPrev = nullptr;
    bool* isFragZeroSeen = nullptr;
    int *iFrag = nullptr;

    ip_header *ih;
    UdpHeader *uh;
    u_int ip_len;
    u_short sport,dport;

    int nPtrn,nPtrnAllocate;
    FrameType *dt = nullptr;
    uint16_t pattern;

    bool flagSetupRx;
};

#endif // WINPCAP_H
