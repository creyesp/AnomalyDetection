#ifndef __SPP_anomalydetection_H__
#define __SPP_anomalydetection_H__

struct profile
{
    struct MIN
    {
        double TcpCountFp;
        double TcpCountFpUp;
        double TcpCountFpDown;
        double LanTcp;
        double UdpCountFp;
        double UdpCountFpUp;
        double UdpCountFpDown;
        double LanUdp;
        double IcmpCountFp;
        double IcmpCountFpUp;
        double IcmpCountFpDown;
        double LanIcmp;
        double SYNACKpNumber;
        double TcpWwwCountUp;
        double TcpWwwCountDown;
        double UdpDnsCountUp;
        double UdpDnsCountDown;
        double ArpRequest;
        double ArpReply;
        double OtherCount;
        double Overall;
        double DataTcpUpKB;
        double DataTcpDownKB;
        double DataWwwUpKB;
        double DataWwwDownKB;
        double DataUdpUpKB;
        double DataUdpDownKB;
        double DataDnsUpKB;
        double DataDnsDownKB;
    } MIN;

    struct MAX
    {
        double TcpCountFp;
        double TcpCountFpUp;
        double TcpCountFpDown;
        double LanTcp;
        double UdpCountFp;
        double UdpCountFpUp;
        double UdpCountFpDown;
        double LanUdp;
        double IcmpCountFp;
        double IcmpCountFpUp;
        double IcmpCountFpDown;
        double LanIcmp;
        double SYNACKpNumber;
        double TcpWwwCountUp;
        double TcpWwwCountDown;
        double UdpDnsCountUp;
        double UdpDnsCountDown;
        double ArpRequest;
        double ArpReply;
        double OtherCount;
        double Overall;
        double DataTcpUpKB;
        double DataTcpDownKB;
        double DataWwwUpKB;
        double DataWwwDownKB;
        double DataUdpUpKB;
        double DataUdpDownKB;
        double DataDnsUpKB;
        double DataDnsDownKB;
    } MAX;
} profile;


typedef struct _AnomalydetectionConfig     
{
    char LogPath[100];
    char ProfilePath[100];
    int nlog;
    int alert;
    int GatherTime;
    float phi;  //porcentaje de las diferencias totales en la ventana de tiempo
    float epsilon; //actor de aproximacion 
    float delta; //probabilidad de falla
    int lgn;  //largo de los bit a considerar de IP, deberia ser 32 version completa en IP
    int groups;   //numero de grupso totales 
    int numberhash; //numero de test hash que se realizan.

} AnomalydetectionConfig;

void SetupAnomalyDetection();

#endif  /* __SPP_anomalydetection_H__ */
