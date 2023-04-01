#include "winpcap.h"

WinPcap::WinPcap(const QString& host_address, QObject *parent) :
    QObject(parent)
    , hostAddress(host_address)
{
    //this shows main (GUI) thread id
    //qDebug() << "Setup Capturing data using PCAP on thread" << QThread::currentThreadId();
    qDebug() << "Setup Capturing data using PCAP" ;

    flagSetupRx = false;
}

void WinPcap::deviceChoice(QList<QString> &devNameList, QList<QString> &devDescList)
{
    qDebug() << "Choose Device" << QThread::currentThreadId();

    i=0;
    char *str =new char[9]{"ok baby"};

    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs_ex(str, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
        {
            printf(" (%s)\n", d->description);
            devNameList << QString(d->name);
            devDescList << QString(d->description);
        }
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    }

    printf("Enter the interface number (1-%d):",i);
}

void WinPcap::setSourceIP(const QString& host_address){
    hostAddress = host_address;
}

int WinPcap::setupRx(int iDev)
{
    flagSetupRx = false;

    struct bpf_program fcode;

    if(iDev < 1 || iDev > i)
    {
        //        printf("\nInterface number out of range.\n");
        qDebug()<< "Interface number out of range: " << iDev << ", i = " << i;
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    int temp_i;
    for(d=alldevs, temp_i=0; temp_i< iDev-1 ;d=d->next, temp_i++){
        //qDebug() << d->description;
    }

    qDebug() << "Device is Chosen: " << d->description;

    std::string packet_exp = "ip and udp and src host " + hostAddress.toStdString();
    const char *packet_filter1 = packet_exp.c_str();
    qDebug() << "packet_exp: " << QString::fromStdString(packet_exp);
    //char *packet_filter1=new char[40]{"ip and udp and src host 192.168.1.100"}; //do not set this manually

    printf("\packet_filter: %s\n",packet_filter1);
    //    packet_filter = "";

    /* Open the device */
    if ( (adHandle= pcap_open(d->name,          // name of the device
                              65536,            // portion of the packet to capture.
                              // 65536 guarantees that the whole packet will be captured on all the link layers
                              PCAP_OPENFLAG_PROMISCUOUS||PCAP_OPENFLAG_MAX_RESPONSIVENESS ,    // promiscuous mode
                              1000,             // read timeout
                              NULL,             // authentication on the remote machine
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        //        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        qDebug()<< "Unable to open the adapter";
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adHandle) != DLT_EN10MB)
    {
        //        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        qDebug()<< "This program works only on Ethernet networks";
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;


    //compile the filter
    if (pcap_compile(adHandle, &fcode, packet_filter1, 1, netmask) <0 )
    {
        //        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        qDebug()<< "Unable to compile the packet filter. Check the syntax";
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(adHandle, &fcode)<0)
    {
        //        fprintf(stderr,"\nError setting the filter.\n");
        qDebug()<< "Error setting the filter";
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    pcap_setbuff(adHandle,128*1024*1024);
    pcap_setmintocopy(adHandle,0);

    //    pcap_freealldevs(alldevs);
    flagSetupRx = true;

    /* At this point, we don&apos;t need any more the device list. Free it */ //we do need it now
    //pcap_freealldevs(alldevs);

    return 0;
}

void WinPcap::setFilter(const uint16_t& port, const uint16_t& frame_len,const uint16_t& patternSync,const uint16_t& fragment)
{
    nPtrnAllocate = 1;
    nPtrn = nPtrnAllocate;
    delete[] fragNow;
    delete[] fragPrev;
    delete[] isFragZeroSeen;
    delete[] iFrag;
    if(dt != nullptr){
        for(int i{}; i < nPtrnAllocate; ++i)
            delete[] dt[i].array;
    }
    delete[] dt; //what about dt.array? bad practice
    fragNow = new ushort[nPtrnAllocate];
    fragPrev = new ushort[nPtrnAllocate];
    isFragZeroSeen = new bool[nPtrnAllocate];
    iFrag = new int[nPtrnAllocate];
    dt = new FrameType[nPtrnAllocate];

    for(int i=0; i<nPtrnAllocate; ++i)
    {
        isFragZeroSeen[i] = false;
        iFrag[i] = 0;
    }

    dt[0].pattern = ntohs(patternSync);
    dt[0].nfrags = fragment;
    qDebug()<<"nfrags"<<dt[0].nfrags;
    dt[0].fragLen = 4;
    dt[0].len = frame_len;
    dt[0].blockSize = dt[0].len*dt[0].nfrags;
    dt[0].array = new u_char[dt[0].blockSize];
    dt[0].port = port;
}

void WinPcap::resetFilterParams(){
    for(int i=0; i<nPtrnAllocate; ++i)
    {
        isFragZeroSeen[i] = false;
        iFrag[i] = 0;
    }
}

int WinPcap::next(void **data, int &size, int &type, int &freqIdx)
{
    if(!flagSetupRx)
        return -2;
    int i = 0;
    size = 0;
    type = -1;
    freqIdx = -1;

    /* Retrieve the packets */
    res = pcap_next_ex( adHandle, &header, &pkt_data);

    if(res <= 0)
    {
        return res;
    }


    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data + 14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (UdpHeader *) ((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( uh->sport );
    dport = ntohs( uh->dport );

    pattern = *(uint16_t *) (pkt_data+42);
//    qDebug() << "Pattern" << pattern << ntohs(0xfeef)<<(dt[0].pattern);
//    if(header->len == (dt[i].len+42))
//        qDebug()<<ntohs(*(ushort *) (pkt_data+36));

    for(i=0; i<nPtrn; ++i)
    {
        if((header->len == (dt[i].len+dt[i].fragLen+42)) & (ntohs(*(ushort *) (pkt_data+36)) ==dt[i].port) & pattern==dt[i].pattern)
//        if((header->len == (dt[i].len+dt[i].fragLen+42)) & (ntohs(*(ushort *) (pkt_data+36)) ==dt[i].port))
        {
            if(isFragZeroSeen[i])
            {
                if(dt[i].nfrags > 1)
                    fragPrev[i] = fragNow[i] + 1;
                else
                    fragPrev[i] = fragNow[i];

                fragNow[i] = ntohs(*(ushort *) (pkt_data+42+2));
                if(fragNow[i] == fragPrev[i])
                {
                    memcpy(dt[i].array+fragNow[i]*dt[i].len,pkt_data+42+4,dt[i].len); // 42 + 2 fragment + 2 freqidx
                    iFrag[i]=fragNow[i]+1; //
                }
                else
                {
                    isFragZeroSeen[i] = false;
                    qDebug() << "UDP Loss !!! res: " << res << "FragPrev: " << fragPrev[i] << ", FragNow: "<<fragNow[i];

                    break;
                }
            }
            else
            {
                fragNow[i] = ntohs(*(ushort *) (pkt_data+42+2));
                if(fragNow[i] == 0)
                {
                    isFragZeroSeen[i] = true;
                    iFrag[i] = 0;
                    memcpy(dt[i].array,pkt_data+42+4,dt[i].len); // 42 + 4 header + 2 fragment + 2 freqidx
                }

            }
            break;
        }
    }

    if((iFrag[i] == dt[i].nfrags) && isFragZeroSeen[i])
    {
        *data = dt[i].array;
        size = dt[i].blockSize;
        type = i+1;
        isFragZeroSeen[i] = false;
        //qDebug() << "Type" << type;
    }

    return res;
}
