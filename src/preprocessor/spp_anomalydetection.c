#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#define _GNU_SOURCE
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>
#include <time.h>
#include <sys/timeb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "generators.h"
#include "event_wrapper.h"
#include "util.h"
#include "plugbase.h"
#include "parser.h"
#include "snort.h"
#include "mstring.h"
#include <stdio.h>
#include "spp_anomalydetection.h"
#include "session_api.h"

/* biblioteca para encontrar los deltoides*/
#include "cgt.h"
#include <math.h>

CGT_type *cgt, *cgt_old;
VGT_type *vgt;
/* variables que de deben ingresar desde el archivo de configiracion*/
int range; 
float phi = 0.001; //porcentaje de las diferencias totales en la ventana de tiempo
float epsilon =  0.0008; //factor de aproximacion 
float delta = 0.063; //probabilidad de falla
int gran = 1; //granularidad, cantidad de bit que se toman para hacer la cuenta.
int lgn = 20; //largo de los bit a considerar de IP, deberia ser 32 version completa en IP
int thesh;


uint64_t TcpCount=0;
uint64_t TcpCountF=0;       
uint64_t TcpCountFp=0;
uint64_t TcpCountFpUp=0;
uint64_t TcpCountFpDown=0;
uint64_t UdpCount=0;
uint64_t UdpCountF=0;
uint64_t UdpCountFp=0;
uint64_t UdpCountFpUp=0;
uint64_t UdpCountFpDown=0;
uint64_t IcmpCount=0;
uint64_t IcmpCountF=0;
uint64_t IcmpCountFp=0;
uint64_t IcmpCountFpUp=0;
uint64_t IcmpCountFpDown=0;
uint64_t IpCount=0;
uint64_t IpCountF=0;
uint64_t LanUdp=0;
uint64_t LanIcmp=0;
uint64_t LanTcp=0;
uint64_t LanUdpF=0;
uint64_t LanIcmpF=0;
uint64_t LanTcpF=0;
uint64_t ArpRequest=0;
uint64_t ArpReply=0;
uint64_t ArpRequestF=0;
uint64_t ArpReplyF=0;
uint64_t OtherCount=0;
uint64_t OtherCountF=0;
uint64_t Overall = 0;
uint64_t OverallF = 0;



int GatherTime=600, TimeInterval;
uint64_t TcpWwwCountDown=0,TcpWwwCountUp=0,UdpDnsCountUp=0,UdpDnsCountDown=0,SynNumberACK=0,SYNACKpNumber,ArpCount=0,ArpCountF=0, Data=0;
double DataKB=0,Datatemp=0,DataTcpDownKB=0,DataTcpUpKB=0,DataWwwDownKB=0,DataWwwUpKB=0,DataUdpDownKB=0,DataUdpUpKB=0,DataDnsUpKB=0,DataDnsDownKB=0;

FILE *fptr,*file1,*file2,*file3;
time_t LastLogTime, CurrentTime;

char FullFileName[50];
char FullPathName[50];

int flag=0, alert=0, nlog=0, check=1;

/************** Bloque de nuevas funciones y variables **************/

#ifdef PERF_PROFILING
PreprocStats ad_perf_stats;
#endif

tSfPolicyUserContextId anomalydetection_config = NULL; //puntero a la estructura tSfPolicyUserContext el cual contienen el id y el el puntero alos archivos de configuracion
AnomalydetectionConfig *anomalydetection_eval_config = NULL;
static void AD_CleanExit(int, void*);
static void AD_Reset(int, void*);
static void AD_PostConfigInit(struct _SnortConfig *, void*);
static int AD_CheckConfig (struct _SnortConfig *);
static void AD_ResetStats(int, void*);
static void AD_PrintStats(int);
static void PrintConf_AD (const AnomalydetectionConfig*);


/************** Fin de funciones nuevas ****************************/
static void AnomalyDetectionInit(struct _SnortConfig *sc, char *args);
static void ParseAnomalyDetectionArgs(AnomalydetectionConfig*, char *);
static void PreprocFunction(Packet *, void *);
static void PreprocCleanExitFunction(int, void *);
static void ADPrintStats(int);
void SaveToLog(time_t);
void ReadProfile(void);
static void ReadLog(void);
time_t CompleteLog(time_t,time_t);

/************** RELOAD ****************************/
#ifdef SNORT_RELOAD
static void AnomalyDetectionReload(struct _SnortConfig *, char *, void **);
static int AnomalyDetectionReloadVerify(struct _SnortConfig *, void *);
static void * AnomalyDetectionReloadSwap(struct _SnortConfig *, void *);
static void AnomalyDetectionReloadSwapFree(void *);
#endif

void SetupAnomalyDetection(void)
{    
    // RegisterPreprocessor("AnomalyDetection", AnomalyDetectionInit);
 #ifndef SNORT_RELOAD
     RegisterPreprocessor("AnomalyDetection", AnomalyDetectionInit);
 #else
     RegisterPreprocessor("AnomalyDetection", AnomalyDetectionInit, AnomalyDetectionReload,
                          NULL, AnomalyDetectionReloadSwap,
                          AnomalyDetectionReloadSwapFree);
     // RegisterPreprocessor("AnomalyDetection", AnomalyDetectionInit, AnomalyDetectionReload,
     //                      AnomalyDetectionReloadVerify, AnomalyDetectionReloadSwap,
     //                      AnomalyDetectionReloadSwapFree);
#endif
    LogMessage("AnomalyDetection : AnomalyDetection is setup\n");

}



/* Function: AnomalyDetectionInit(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 */

static void AnomalyDetectionInit(struct _SnortConfig *sc, char *args)
{
    /*********************************************************************/
    /*calculo que se debe realizar en init*/
    int groups = (int) ((2/epsilon)+1);
    int hashtest = (int) ((log10((double) 1/delta)/log10(2))+1);
    /***********************************************************************/
    LogMessage("----------AD-Init: AnomalyDetectionInit started.\n");
    // tSfPolicyId policy_id = getParserPolicy(NULL);
    int policy_id = (int) getParserPolicy(sc);
    AnomalydetectionConfig *pPolicyConfig = NULL;

    if ( anomalydetection_config == NULL)
    {
        //create a context
        anomalydetection_config = sfPolicyConfigCreate();
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: Anomaly Detection Initialized\n"););


#ifdef PERF_PROFILING
        RegisterPreprocessorProfile(
            "anomalydetection", &ad_perf_stats, 0, &totalPerfStats);
#endif
        AddFuncToPreprocCleanExitList(
            AD_CleanExit, NULL, PRIORITY_SCANNER, PP_SFPORTSCAN); // borra punteros y espacios de memoria antes de cerrar

        // AddFuncToPreprocResetList(
        //     AD_Reset, NULL, PRIORITY_SCANNER, PP_SFPORTSCAN); // sin implementar

        // AddFuncToPreprocResetStatsList(
        //     AD_ResetStats, NULL, PRIORITY_SCANNER, PP_SFPORTSCAN); //sin implementar

        // AddFuncToConfigCheckList(sc, AD_CheckConfig);
        // AddFuncToPreprocPostConfigList(sc, AD_PostConfigInit, NULL);//sin implementacion
        RegisterPreprocStats("anomalydetection", AD_PrintStats); //imprime un informe cuando snort cierra

    }

    sfPolicyUserPolicySet(anomalydetection_config, policy_id);
    pPolicyConfig = (AnomalydetectionConfig *)sfPolicyUserDataGetCurrent(anomalydetection_config);
    if (pPolicyConfig)
    {
        ParseError("AnomalyDetection preprocessor can only be configured once.\n");
    }

    pPolicyConfig = (AnomalydetectionConfig* )SnortAlloc(sizeof(AnomalydetectionConfig)); 
    if (!pPolicyConfig)
    {
        ParseError("AnomalyDetection preprocessor: memory allocate failed.\n");
    }

    sfPolicyUserDataSetCurrent(anomalydetection_config, pPolicyConfig);

    /* Process argument list */
    ParseAnomalyDetectionArgs(pPolicyConfig, args);
    LogMessage("#groups: %d #hashtest: %d\n",groups, hashtest);
    cgt = CGT_Init(groups,hashtest,lgn);
    vgt = VGT_Init(groups,hashtest,lgn);



    // if ( !pPolicyConfig)
    // {
    //     pPolicyConfig = (AnomalydetectionConfig* )SnortAlloc(sizeof(AnomalydetectionConfig)); 
    //     sfPolicyUserDataSetCurrent(anomalydetection_config, pPolicyConfig);   
        //AddFuncToPreprocList( sc, PreprocFunction, PRIORITY_FIRST,  PP_ENABLE_ALL, PROTO_BIT__ALL);
        AddFuncToPreprocList( sc, PreprocFunction, PRIORITY_SCANNER,  PP_SFPORTSCAN, PROTO_BIT__ALL);
        session_api->enable_preproc_all_ports( sc, PP_SFPORTSCAN, PROTO_BIT__ALL );
    // }
    
/*  ********************************************************************************** */

    LogMessage("----------AD-Init: AnomalyDetection Initialized\n");

    // ParseAnomalyDetectionArgs((char*)args);

    // AddFuncToPreprocList(sc, PreprocFunction,PRIORITY_FIRST,PP_ENABLE_ALL,PROTO_BIT__ALL);
//    AddFuncToPreprocList(PreprocFunction,PRIORITY_FIRST,PP_ENABLE_ALL,PROTO_BIT__ALL);

 
    ReadLog();
    if(pPolicyConfig->alert)
        ReadProfile();
}

/* Function: ParseTemplateArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and
 *          initialize the preprocessor's data struct.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 */

static void ParseAnomalyDetectionArgs(AnomalydetectionConfig* pc, char *args)
{
    LogMessage("----------AD-Parse: Parse Anomaly Detection is loading.\n");
    int positionPath = 0;
    char **tokens=NULL;
    char *pcEnd;
    int toknum=0, i;
    char aux[100];
    if (args) tokens=mSplit(args," \t",50,&toknum,'\\');
    for (i=0; i<toknum; i++)
    {
        LogMessage("----------AD-Parse: TOKEN: %s.\n",tokens[i]);
        if (!strcasecmp(tokens[i], "alert")) 
        {    // alert=1;
            pc->alert = 1;
        }

        if (!strcasecmp(tokens[i], "log")) 
        {
            // nlog=1;
            pc->nlog = 1;
        }

        if (!strcasecmp(tokens[i], "time")) 
        {
            pc->GatherTime = strtol(tokens[++i], &pcEnd, 10);

            if(pc->GatherTime < 1)
                pc->GatherTime = 1;
        }

        if (!strcasecmp(tokens[i], "ProfilePath")) 
        {
            // sprintf(FullFileName, "%s", tokens[++i]); 
            sprintf(pc->ProfilePath, "%s", tokens[++i]);

        }

        if (!strcasecmp(tokens[i], "LogPath")) 
        {
           positionPath=++i;
        }

        LogMessage("----------AD-Parse: FIN DEL FOR.......\n");
    }


    if(positionPath)
        sprintf(pc->LogPath, "%s/ADLog%d.txt", tokens[positionPath], pc->GatherTime);
    else
        sprintf(pc->LogPath, "/var/log/snort/ADLog%d.txt", pc->GatherTime);

    LogMessage("----------AD-Parse: antes de ProfilePath\n");
    if(!pc->ProfilePath)
    {
        LogMessage("----------AD-Parse: antes de asignar ProfilePath\n");
        sprintf(pc->ProfilePath, "/usr/local/etc/snort/profile.txt");
     //    strcpy(pc->ProfilePath,aux);
        // LogMessage("----------AD-Parse: antes de asignar ProfilePath\n");
    }
    PrintConf_AD(pc);

    // if(p==-1)
        // sprintf(FullPathName, "/var/log/snort/ADLog%d.txt", GatherTime);
    // else sprintf(FullPathName, "%s/ADLog%d.txt", tokens[p], GatherTime);
}

/* Function: CollectData(Packet *)
 *
 * Purpose: Perform the statistics collection.
 *
 * Arguments: p => pointer to the current packet data struct
 *
 * Returns: void function
 */

void CollectData(Packet *p)
{
    sfip_t *pdst, *psrc;
    if(p->tcph!=NULL)
    {
        pdst = GET_DST_IP(p);
        psrc = GET_SRC_IP(p);
        TcpCount++;
        Overall++;
        OverallF++;
        TcpCountF++;
        TcpCountFp++;

    if((sfip_contains(&snort_conf->homenet,pdst) == SFIP_CONTAINS) && (sfip_contains(&snort_conf->homenet,psrc) == SFIP_CONTAINS))
        {
            LanTcp++;
            LanTcpF++;
        }else
        {
            if(sfip_contains(&snort_conf->homenet,pdst) == SFIP_CONTAINS)
            {
                TcpCountFpDown++;
                DataTcpDownKB+=((double)(p->actual_ip_len)/1024);
                if(p->tcph->th_sport==htons(80))
                {
                    TcpWwwCountDown++;
                    DataWwwDownKB+=((double)(p->actual_ip_len)/1024);
                }
            }
            else if(sfip_contains(&snort_conf->homenet,psrc) == SFIP_CONTAINS)
            {
                TcpCountFpUp++;
                DataTcpUpKB+=((double)(p->actual_ip_len)/1024);
                if(p->tcph->th_dport==htons(80))
                {
                    TcpWwwCountUp++;
                    DataWwwUpKB+=((double)(p->actual_ip_len)/1024);
                }
            }
        }

        if(((p->tcph->th_flags)&2)&&((p->tcph->th_flags)&16))
        {
            SynNumberACK++;
            SYNACKpNumber++;
        }
    }
    else if(p->udph!=NULL)
    {
        pdst = GET_DST_IP(p);
        psrc = GET_SRC_IP(p);
        UdpCount++;
        Overall++;
        OverallF++;
        UdpCountF++;
        UdpCountFp++;

    if((sfip_contains(&snort_conf->homenet,pdst) == SFIP_CONTAINS) && (sfip_contains(&snort_conf->homenet,psrc) == SFIP_CONTAINS))
        {
            LanUdp++;
            LanUdpF++;
        }else
        {
            if(sfip_contains(&snort_conf->homenet,pdst) == SFIP_CONTAINS)
            {
                UdpCountFpDown++;
                DataUdpDownKB+=((double)(p->actual_ip_len)/1024);
                if(p->udph->uh_sport==htons(53))
                {
                    UdpDnsCountDown++;
                    DataDnsDownKB+=((double)(p->actual_ip_len)/1024);
                }
            }
            else if(sfip_contains(&snort_conf->homenet,psrc) == SFIP_CONTAINS)
            {
                UdpCountFpUp++;
                DataUdpUpKB+=((double)(p->actual_ip_len)/1024);
                if(p->udph->uh_dport==htons(53))
                {
                    UdpDnsCountUp++;
                    DataDnsUpKB+=((double)(p->actual_ip_len)/1024);
                }
            }
        }
    }
    else if(p->icmph!=NULL)
    {
        pdst = GET_DST_IP(p);
        psrc = GET_SRC_IP(p);
        IcmpCount++;
        Overall++;
        OverallF++;
        IcmpCountF++;
        IcmpCountFp++;
    
    if((sfip_contains(&snort_conf->homenet,pdst) == SFIP_CONTAINS) && (sfip_contains(&snort_conf->homenet,psrc) == SFIP_CONTAINS))
        {
            LanIcmp++;
            LanIcmpF++;
        }else
        {
            if(sfip_contains(&snort_conf->homenet,pdst) == SFIP_CONTAINS)
                IcmpCountFpDown++;
            else if(sfip_contains(&snort_conf->homenet,psrc) == SFIP_CONTAINS)
                IcmpCountFpUp++;
        }   
    }
    else if(p->iph!=NULL)
    {
        IpCount++;
        Overall++;
        OverallF++;
        IpCountF++;
    }
    else if(p->ah!=NULL)
    {
        ArpCount++;
        Overall++;
        OverallF++;
        ArpCountF++;

        if(ntohs(p->ah->ea_hdr.ar_op)==1)
        {
            ArpRequest++;
            ArpRequestF++;
        }
        if(ntohs(p->ah->ea_hdr.ar_op)==2)
        {
            ArpReply++;
            ArpReplyF++;
        }
    }
    else
    {
        OtherCount++;
        OtherCountF++;
        Overall++;
        OverallF++;
    }
}


static void CGT(Packet *p)
{
    unsigned int ip;
    int packetsize;
    sfip_t *psrc;

    if(p->tcph!=NULL)
    {
        psrc = GET_SRC_IP(p);
        ip = (unsigned int) psrc->ip32;
        packetsize = 1;
        CGT_Update(cgt, ip, packetsize); 
        VGT_Update(vgt, ip, packetsize); 
    }
}


int compare (const void * a, const void * b)
{
  return (*(float*)a >= *(float*)b) ? 1 : -1;
}

static int ComputeThresh(CGT_type *cgt)
{
    //hashtest
    //groups
    /*********************************************************************/
    /*calculo que se debe realizar en init*/
    int groups = (int) ((2/epsilon)+1);
    int hashtest = (int) ((log10((double) 1/delta)/log10(2))+1);
    /***********************************************************************/

    int ihash, jgroup;
    float count[hashtest];
    for(ihash = 0; ihash < hashtest; ihash++)
    {
        count[ihash] = 0;
        for(jgroup = 0; jgroup < groups; jgroup++)
        {
            count[ihash] += cgt->counts[ihash*hashtest+jgroup][0];
        }
    }

    qsort(count, hashtest, sizeof(float), compare);
    LogMessage("#packet: %d | threshold: %1.1f",cgt->count,count[(int)hashtest/2]);
    
    return (int)phi*count[(int)hashtest/2];

}
/* Function: PreprocFunction(Packet *)
 *
 * Purpose: Main preprocessor function. Aalerts and logs are generated here.
 *
 * Arguments: p => pointer to the current packet data struct
 *
 * Returns: void function
 */

static void PreprocFunction(Packet *p,void *context)
{   
    /*********************************************************************/
    /*calculo que se debe realizar en init*/
    int groups = (int) ((2/epsilon)+1);
    int hashtest = (int) ((log10((double) 1/delta)/log10(2))+1);
    /***********************************************************************/

    //CGT_type *cgt_aux;
    tSfPolicyId pid = getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(anomalydetection_config, pid);
    unsigned int *outputList;
    int i;
    //struct in_addr addr;

    if(flag==0) //check if it is new file, all new log files need to have header
    {
        file2=fopen(pc->LogPath,"a");
        if ( file2 != NULL && ftell(file2) == 0 )
        {
        LogMessage("AnomalyDetection: Creating new log file in %s.\n",pc->LogPath);
            fprintf(file2,"DD-MM-YY, HH:MM:SS, Day of the Week, Time interval [s], TCP summary [number of packet], TCP outgoing [number of packet], TCP incoming [number of packet], TCP from this subnet [number of packet], UDP summary [number of packet], UDP outgoing [number of packet], UDP incoming [number of packet], UDP from this subnet [numbber of packet], ICMP summary [number of packet], ICMP outgoing [number of packet], ICMP incoming [number of packet], ICMP from this subnet [number of packet], TCP with SYN/ACK [number of packets], WWW outgoing - TCP outgoing to port 80 [number of packet], WWW incoming - TCP incoming from port 80 [number of packet], DNS outgoing - UDP outgoing to port 53 [number of packet], DNS incoming - UDP incoming from port 53 [number of packet], ARP-request [number of packet], ARP-reply [number of packet], Not TCP/IP stacks packet [number of packet], Total [number of packet], TCP upload speed [kBps], TCP download speed [kBps], WWW upload speed [kBps], WWW download speed [kBps], UDP upload speed [kBps], UDP download speed [kBps], DNS upload speed [kBps], DNS download speed [kBps]\n");
            time(&LastLogTime);
        }else LogMessage("AnomalyDetection: Opened an existing log file named AD%d.txt\n",pc->GatherTime);
        fclose(file2);
        flag=1;
    }

    time(&CurrentTime);
    TimeInterval=CurrentTime-LastLogTime;
    char OldTimeStamp[20],NewTimeStamp[20];   
    struct tm *oldtm,*newtm;
    oldtm = localtime(&LastLogTime);
    strftime(OldTimeStamp,sizeof(OldTimeStamp),"%d-%m-%y %T", oldtm);
    
    if(TimeInterval >= pc->GatherTime)
    {
        LastLogTime += GatherTime;

        if (pc->nlog) //if flag "log" is set in config file, preprocessor will log stats to file
        {
            SaveToLog(LastLogTime); //save in the log file the current count data
     
            newtm = localtime(&LastLogTime);
            strftime(NewTimeStamp,sizeof(NewTimeStamp),"%d-%m-%y %T", newtm);
            LogMessage("AnomalyDetection: Loged transfer between %s - %s\n",OldTimeStamp,NewTimeStamp);
            //Aplicar testing sobre 
            
            outputList = CGT_Output(cgt, vgt, ComputeThresh(cgt));
            LogMessage("NUMERO DE SALIDAS; %d\n",outputList[0]);
            for(i=1; i < outputList[0]; i++)
            {
                //addr = (struct in_addr) outputList[i] ;
                //LogMessage("%s - %s  ||  %s\n",OldTimeStamp,NewTimeStamp, inet_ntoa(addr));
                LogMessage("%s - %s  ||  %d\n",OldTimeStamp,NewTimeStamp, outputList[i]);
            }
            //cgt_aux = cgt_old;
            //cgt_old = cgt;
            //CGT_Destroy(cgt_aux);
            CGT_Destroy(cgt);
            VGT_Destroy(vgt);
            cgt = CGT_Init(groups,hashtest,lgn);
            vgt = VGT_Init(groups,hashtest,lgn);
        }
     
        if (pc->alert)  //if flag "alert" is set in config file, preprocessor will generate alerts
        {
            if(check)
            {
                if (profile.MIN.TcpCountFp>TcpCountFp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_UNUSUALLY_LOW_TCP_TRAFFIC,1,999,1,"AD_UNUSUALLY_LOW_TCP_TRAFFIC");
                if (profile.MAX.TcpCountFp<TcpCountFp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_UNUSUALLY_HIGH_TCP_TRAFFIC,1,999,1,"AD_UNUSUALLY_HIGH_TCP_TRAFFIC");
                if (profile.MIN.TcpCountFpDown>TcpCountFpDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_INCOMING_TCP_TRAFFIC,1,999,1,"AD_LOW_INCOMING_TCP_TRAFFIC");                
                if (profile.MAX.TcpCountFpDown<TcpCountFpDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_INCOMING_TCP_TRAFFIC,1,999,1,"AD_HIGH_INCOMING_TCP_TRAFFIC");
                if (profile.MIN.TcpCountFpUp>TcpCountFpUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_OUTGOING_TCP_TRAFFIC,1,999,1,"AD_LOW_OUTGOING_TCP_TRAFFIC");
                if (profile.MAX.TcpCountFpUp<TcpCountFpUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_OUTGOING_TCP_TRAFFIC,1,999,1,"AD_HIGH_OUTGOING_TCP_TRAFFIC");
                if (profile.MIN.LanTcp>LanTcp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_LAN_TCP_TRAFFIC,1,999,1,"AD_LOW_LAN_TCP_TRAFFIC");
                if (profile.MAX.LanTcp<LanTcp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_LAN_TCP_TRAFFIC,1,999,1,"AD_HIGH_LAN_TCP_TRAFFIC");
                if (profile.MIN.UdpCountFp>UdpCountFp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_UNUSUALLY_LOW_UDP_TRAFFIC,1,999,1,"AD_UNUSUALLY_LOW_UDP_TRAFFIC");
                if (profile.MAX.UdpCountFp<UdpCountFp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_UNUSUALLY_HIGH_UDP_TRAFFIC,1,999,1,"AD_UNUSUALLY_HIGH_UDP_TRAFFIC");
                if (profile.MIN.UdpCountFpUp>UdpCountFpUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_OUTGOING_UDP_TRAFFIC,1,999,1,"AD_LOW_OUTGOING_UDP_TRAFFIC");
                if (profile.MAX.UdpCountFpUp<UdpCountFpUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_OUTGOING_UDP_TRAFFIC,1,999,1,"AD_HIGH_OUTGOING_UDP_TRAFFIC");
                if (profile.MIN.UdpCountFpDown>UdpCountFpDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_INCOMING_UDP_TRAFFIC,1,999,1,"AD_LOW_INCOMING_UDP_TRAFFIC");
                if (profile.MAX.UdpCountFpDown<UdpCountFpDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_INCOMING_UDP_TRAFFIC,1,999,1,"AD_HIGH_INCOMING_UDP_TRAFFIC");
                if (profile.MIN.LanUdp>LanUdp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_LAN_UDP_TRAFFIC,1,999,1,"AD_LOW_LAN_UDP_TRAFFIC");
                if (profile.MAX.LanUdp<LanUdp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_LAN_UDP_TRAFFIC,1,999,1,"AD_HIGH_LAN_UDP_TRAFFIC");
                if (profile.MIN.IcmpCountFp>IcmpCountFp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_UNUSUALLY_LOW_ICMP_TRAFFIC,1,999,1,"AD_UNUSUALLY_LOW_ICMP_TRAFFIC");
                if (profile.MAX.IcmpCountFp<IcmpCountFp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_UNUSUALLY_HIGH_ICMP_TRAFFIC,1,999,1,"AD_UNUSUALLY_HIGH_ICMP_TRAFFIC");
                if (profile.MIN.IcmpCountFpUp>IcmpCountFpUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_OUTGOING_ICMP_TRAFFIC,1,999,1,"AD_LOW_OUTGOING_ICMP_TRAFFIC");
                if (profile.MAX.IcmpCountFpUp<IcmpCountFpUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_OUTGOING_ICMP_TRAFFIC,1,999,1,"AD_HIGH_OUTGOING_ICMP_TRAFFIC");
                if (profile.MIN.IcmpCountFpDown>IcmpCountFpDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_INCOMING_ICMP_TRAFFIC,1,999,1,"AD_LOW_INCOMING_ICMP_TRAFFIC");
                if (profile.MAX.IcmpCountFpDown<IcmpCountFpDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_INCOMING_ICMP_TRAFFIC,1,999,1,"AD_HIGH_INCOMING_ICMP_TRAFFIC");
                if (profile.MIN.LanIcmp>LanIcmp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_LAN_ICMP_TRAFFIC,1,999,1,"AD_LOW_LAN_ICMP_TRAFFIC");
                if (profile.MAX.LanIcmp<LanIcmp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_LAN_ICMP_TRAFFIC,1,999,1,"AD_HIGH_LAN_ICMP_TRAFFIC");
                if (profile.MIN.SYNACKpNumber>SYNACKpNumber) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_SYNACK_PACKET_NUMBER,1,999,1,"AD_LOW_SYN/ACK_PACKET_NUMBER");
                if (profile.MAX.SYNACKpNumber<SYNACKpNumber) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_SYNACK_PACKET_NUMBER,1,999,1,"AD_HIGH_SYN/ACK_PACKET_NUMBER");
                if (profile.MIN.TcpWwwCountUp>TcpWwwCountUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_OUTGOING_HTTP_TRAFFIC,1,999,1,"AD_LOW_OUTGOING_HTTP_TRAFFIC");
                if (profile.MAX.TcpWwwCountUp<TcpWwwCountUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_OUTGOING_HTTP_TRAFFIC,1,999,1,"AD_HIGH_OUTGOING_HTTP_TRAFFIC");
                if (profile.MIN.TcpWwwCountDown>TcpWwwCountDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_INCOMING_HTTP_TRAFFIC,1,999,1,"AD_LOW_INCOMING_HTTP_TRAFFIC");
                if (profile.MAX.TcpWwwCountDown<TcpWwwCountDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_INCOMING_HTTP_TRAFFIC,1,999,1,"AD_HIGH_INCOMING_HTTP_TRAFFIC");
                if (profile.MIN.UdpDnsCountUp>UdpDnsCountUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_OUTGOING_DNS_TRAFFIC,1,999,1,"AD_LOW_OUTGOING_DNS_TRAFFIC");
                if (profile.MAX.UdpDnsCountUp<UdpDnsCountUp) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_OUTGOING_DNS_TRAFFIC,1,999,1,"AD_HIGH_OUTGOING_DNS_TRAFFIC");
                if (profile.MIN.UdpDnsCountDown>UdpDnsCountDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_INCOMING_DNS_TRAFFIC,1,999,1,"AD_LOW_INCOMING_DNS_TRAFFIC");
                if (profile.MAX.UdpDnsCountDown<UdpDnsCountDown) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_INCOMING_DNS_TRAFFIC,1,999,1,"AD_HIGH_INCOMING_DNS_TRAFFIC");
                if (profile.MIN.ArpRequest>ArpRequest) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_ARP_REQUEST_NUMBER,1,999,1,"AD_LOW_ARP_REQUEST_NUMBER");
                if (profile.MAX.ArpRequest<ArpRequest) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_ARP_REQUEST_NUMBER,1,999,1,"AD_HIGH_ARP_REQUEST_NUMBER");
                if (profile.MIN.ArpReply>ArpReply) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_ARP_REPLY_NUMBER,1,999,1,"AD_LOW_ARP_REPLY_NUMBER");
                if (profile.MAX.ArpReply<ArpReply) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_ARP_REPLY_NUMBER,1,999,1,"AD_HIGH_ARP_REPLY_NUMBER");
                if (profile.MIN.OtherCount>OtherCount) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_NOT_TCPIP_TRAFFIC,1,999,1,"AD_LOW_NOT_TCP/IP_TRAFFIC");
                if (profile.MAX.OtherCount<OtherCount) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_NOT_TCPIP_TRAFFIC,1,999,1,"AD_HIGH_NOT_TCP/IP_TRAFFIC");
                if (profile.MIN.Overall>Overall) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_OVERALL_PACKET_NUMBER,1,999,1,"AD_LOW_OVERALL_PACKET_NUMBER");
                if (profile.MAX.Overall<Overall) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_OVERALL_PACKET_NUMBER,1,999,1,"AD_HIGH_OVERALL_PACKET_NUMBER");
                if (profile.MIN.DataTcpUpKB>DataTcpUpKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_VALUE_OF_UPLOAD_TCP_DATA_SPEED,1,999,1,"AD_LOW_VALUE_OF_UPLOAD_TCP_DATA_SPEED");
                if (profile.MAX.DataTcpUpKB<DataTcpUpKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_UPLOAD_TCP_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_UPLOAD_TCP_DATA_SPEED");
                if (profile.MIN.DataTcpDownKB>DataTcpDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_VALUE_OF_DOWNLOAD_TCP_DATA_SPEED,1,999,1,"AD_LOW_VALUE_OF_DOWNLOAD_TCP_DATA_SPEED");
                if (profile.MAX.DataTcpDownKB<DataTcpDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_DOWNLOAD_TCP_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_DOWNLOAD_TCP_DATA_SPEED");
                if (profile.MIN.DataWwwUpKB>DataWwwUpKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_VALUE_OF_UPLOAD_HTTP_DATA_SPEED,1,999,1,"AD_LOW_VALUE_OF_UPLOAD_HTTP_DATA_SPEED");
                if (profile.MAX.DataWwwUpKB<DataWwwUpKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_UPLOAD_HTTP_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_UPLOAD_HTTP_DATA_SPEED");
                if (profile.MIN.DataWwwDownKB>DataWwwDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_VALUE_OF_DOWNLOAD_HTTP_DATA_SPEED,1,999,1,"AD_LOW_VALUE_OF_DOWNLOAD_HTTP_DATA_SPEED");
                if (profile.MAX.DataWwwDownKB<DataWwwDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_DOWNLOAD_HTTP_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_DOWNLOAD_HTTP_DATA_SPEED");
                if (profile.MIN.DataUdpUpKB>DataUdpUpKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_VALUE_OF_UPLOAD_UDP_DATA_SPEED,1,999,1,"AD_LOW_VALUE_OF_UPLOAD_UDP_DATA_SPEED");
                if (profile.MAX.DataUdpUpKB<DataUdpUpKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_UPLOAD_UDP_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_UPLOAD_UDP_DATA_SPEED");
                if (profile.MIN.DataUdpDownKB>DataUdpDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_VALUE_OF_DOWNLOAD_UDP_DATA_SPEED,1,999,1,"AD_LOW_VALUE_OF_DOWNLOAD_UDP_DATA_SPEED");
                if (profile.MAX.DataUdpDownKB<DataUdpDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_DOWNLOAD_UDP_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_DOWNLOAD_UDP_DATA_SPEED");
                if (profile.MIN.DataDnsUpKB>DataDnsUpKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_VALUE_OF_UPLOAD_DNS_DATA_SPEED,1,999,1,"AD_LOW_VALUE_OF_UPLOAD_DNS_DATA_SPEED");
                if (profile.MAX.DataDnsUpKB<DataDnsUpKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_UPLOAD_DNS_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_UPLOAD_DNS_DATA_SPEED");
                if (profile.MIN.DataDnsDownKB>DataDnsDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_LOW_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED,1,999,1,"AD_LOW_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED");
                if (profile.MAX.DataDnsDownKB<DataDnsDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED");
            }
            ReadProfile();
        }

        TcpCountFp=0;
        UdpCountFp=0;
        IcmpCountFp=0;
        TcpCountFpUp=0;
        UdpCountFpUp=0;
        IcmpCountFpUp=0;
        TcpCountFpDown=0;
        UdpCountFpDown=0;
        IcmpCountFpDown=0;
        LanUdp=0;
        LanIcmp=0;
        LanTcp=0;
        SYNACKpNumber=0;
        TcpWwwCountDown=0;
        TcpWwwCountUp=0;
        UdpDnsCountUp=0;
        UdpDnsCountDown=0;
        DataTcpDownKB=0;
        DataTcpUpKB=0;
        DataWwwDownKB=0;
        DataWwwUpKB=0;
        DataUdpDownKB=0;
        DataUdpUpKB=0;
        DataDnsUpKB=0;
        DataDnsDownKB=0;
        ArpRequest = 0;
        ArpReply = 0;
        OtherCount = 0;
        Overall = 0;
        
        // PREPROC_PROFILE_START(ad_perf_stats);

        CollectData(p);
        CGT(p); //agrega el nuevopaquete a la estructura

        // PREPROC_PROFILE_END(ad_perf_stats);


        LastLogTime = CompleteLog(LastLogTime,CurrentTime);
    }
    else{
        CollectData(p);
        CGT(p);
    } 
}
/* Function: SaveToLog(time_t LastLogTime)
 *
 * Purpose: Save current state of containers to log file.
 *
 * Arguments: a => last logging time.
 *            b => current time.
 *
 * Returns: void function
 */

time_t CompleteLog(time_t a,time_t b)
{    
       tSfPolicyId pid = getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(anomalydetection_config, pid);

    TimeInterval=b-a; ///time of sampling in seconds
    char TimeStamp[30];
    struct tm *tmp;
    file2=fopen(pc->LogPath,"a");
    LogMessage("AnomalyDetection : AnomalyDetection is complete Log file.\n");
    while(1)
    {
        if( TimeInterval >= GatherTime )
        {
            a += GatherTime;
            tmp = localtime(&a);
            strftime(TimeStamp,sizeof(TimeStamp), "%d-%m-%y,%H:%M:%S,%a", tmp);
            fprintf(file2,"%s,%d,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00\n",TimeStamp,GatherTime);
            TimeInterval=b-a;
        }
        else
        {
            fclose(file2);
            return a;
        }
    }
}

/* Function: SaveToLog(time_t LastLogTime)
 *
 * Purpose: Save current state of containers to log file.
 *
 * Arguments: LastLogTime => contains the last logging time.
 *
 * Returns: void function
 */

void SaveToLog(time_t LastLogTime)
{
    tSfPolicyId pid = getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(anomalydetection_config, pid);

    char TimeStamp[30];
    struct tm *tmp;
    tmp = localtime(&LastLogTime);
    strftime(TimeStamp,sizeof(TimeStamp),"%d-%m-%y,%T,%a", tmp);
    file2=fopen(pc->LogPath,"a");
    fprintf(file2,"%s,%d,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
        TimeStamp,GatherTime,TcpCountFp,TcpCountFpUp,TcpCountFpDown,LanTcp,UdpCountFp,UdpCountFpUp,UdpCountFpDown,LanUdp,IcmpCountFp,IcmpCountFpUp,IcmpCountFpDown,
        LanIcmp,SYNACKpNumber,TcpWwwCountUp,TcpWwwCountDown,UdpDnsCountUp,UdpDnsCountDown,ArpRequest,ArpReply,OtherCount,Overall,DataTcpUpKB/GatherTime,DataTcpDownKB/GatherTime,
        DataWwwUpKB/GatherTime,DataWwwDownKB/GatherTime,DataUdpUpKB/GatherTime,DataUdpDownKB/GatherTime,DataDnsUpKB/GatherTime,DataDnsDownKB/GatherTime);
    fclose(file2);
}


static void ReadLog(void)
{
    tSfPolicyId pid = getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(anomalydetection_config, pid);
    
    char string[1000];
    char str [17];
    // fptr = fopen(FullPathName, "r");
    fptr = fopen(pc->LogPath, "r");
    if (fptr!=NULL)
    {
        LogMessage("----------AD-ReadLog: Log file opened.\n");
        while(1)
            if(fgets(string,600,fptr)==NULL)
                break;
        fclose(fptr);
        strncpy(str,string,17);

        struct tm tm;
        time_t LastlognTime;
        time(&LastLogTime);
        
        if (strptime(str,"%d-%m-%y,%H:%M:%S", &tm) != NULL)
        {
            LastlognTime = mktime(&tm);
           
            if (LastlognTime == -1)
                LogMessage("----------AD-ReadLog: Can't read last login time.\n");
            else 
                LastLogTime = CompleteLog(LastlognTime,LastLogTime);
        }
        else LogMessage("----------AD-ReadLog: Can't read last login time.\n");
    }
    else LogMessage("----------AD-ReadLog: Log file doesn't exist.\n");
}




/* Function: ReadProfile(void)
 *
 * Purpose: Read proper profile line from file.
 *
 * Arguments: no args
 *
 * Returns: void function
 */

void ReadProfile(void)
{
       tSfPolicyId pid = getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(anomalydetection_config, pid);

    char seps[]=",";
    char string[1000];
    char *token;

    char str2 [19];
    fptr = fopen(pc->LogPath, "r");
    if (fptr!=NULL)
    {
        struct tm *system,log;
        time_t Time,LogTime;
        time(&Time);
        system = localtime(&Time);
        Time-=GatherTime;
        LogMessage("AnomalyDetection: Profile opened.\n");
        while(1)
        {
        if(fgets(string,600,fptr)==NULL)
            {
                LogMessage("AnomalyDetection: Can't read proper profile row\n");
                check=0;
                break;
            }
            strncpy (str2,string,19);

            if(strptime(str2,"%d-%m-%y,%u,%H:%M:%S", &log) != NULL)
            {
                if(system->tm_wday==log.tm_wday)
                {
                    log.tm_year=system->tm_year;
                    log.tm_mon=system->tm_mon;
                    log.tm_mday=system->tm_mday;

                LogTime = mktime(&log);
                    if (LogTime != -1)
                    {
                        if(Time<=LogTime && Time>=LogTime-GatherTime)
                        {
                            token=strtok(string,seps);
                            int i;
                            for (i=0; i<62; i++)
                            {
                                if (i==4) profile.MIN.TcpCountFp=atof(token);
                                if (i==5) profile.MAX.TcpCountFp=atof(token);
                                if (i==6) profile.MIN.TcpCountFpUp=atof(token);
                                if (i==7) profile.MAX.TcpCountFpUp=atof(token);
                                if (i==8) profile.MIN.TcpCountFpDown=atof(token);
                                if (i==9) profile.MAX.TcpCountFpDown=atof(token);
                                if (i==10) profile.MIN.LanTcp=atof(token);
                                if (i==11) profile.MAX.LanTcp=atof(token);
                                if (i==12) profile.MIN.UdpCountFp=atof(token);
                                if (i==13) profile.MAX.UdpCountFp=atof(token);
                                if (i==14) profile.MIN.UdpCountFpUp=atof(token);
                                if (i==15) profile.MAX.UdpCountFpUp=atof(token);
                                if (i==16) profile.MIN.UdpCountFpDown=atof(token);
                                if (i==17) profile.MAX.UdpCountFpDown=atof(token);
                                if (i==18) profile.MIN.LanUdp=atof(token);
                                if (i==19) profile.MAX.LanUdp=atof(token);
                                if (i==20) profile.MIN.IcmpCountFp=atof(token);
                                if (i==21) profile.MAX.IcmpCountFp=atof(token);
                                if (i==22) profile.MIN.IcmpCountFpUp=atof(token);
                                if (i==23) profile.MAX.IcmpCountFpUp=atof(token);
                                if (i==24) profile.MIN.IcmpCountFpDown=atof(token);
                                if (i==25) profile.MAX.IcmpCountFpDown=atof(token);
                                if (i==26) profile.MIN.LanIcmp=atof(token);
                                if (i==27) profile.MAX.LanIcmp=atof(token);
                                if (i==28) profile.MIN.SYNACKpNumber=atof(token);
                                if (i==29) profile.MAX.SYNACKpNumber=atof(token);
                                if (i==30) profile.MIN.TcpWwwCountUp=atof(token);
                                if (i==31) profile.MAX.TcpWwwCountUp=atof(token);
                                if (i==32) profile.MIN.TcpWwwCountDown=atof(token);
                                if (i==33) profile.MAX.TcpWwwCountDown=atof(token);
                                if (i==34) profile.MIN.UdpDnsCountUp=atof(token);
                                if (i==35) profile.MAX.UdpDnsCountUp=atof(token);
                                if (i==36) profile.MIN.UdpDnsCountDown=atof(token);
                                if (i==37) profile.MAX.UdpDnsCountDown=atof(token);
                                if (i==38) profile.MIN.ArpRequest=atof(token);
                                if (i==39) profile.MAX.ArpRequest=atof(token);
                                if (i==40) profile.MIN.ArpReply=atof(token);
                                if (i==41) profile.MAX.ArpReply=atof(token);
                                if (i==42) profile.MIN.OtherCount=atof(token);
                                if (i==43) profile.MAX.OtherCount=atof(token);
                                if (i==44) profile.MIN.Overall=atof(token);
                                if (i==45) profile.MAX.Overall=atof(token);
                                if (i==46) profile.MIN.DataTcpUpKB=atof(token);
                                if (i==47) profile.MAX.DataTcpUpKB=atof(token);
                                if (i==48) profile.MIN.DataTcpDownKB=atof(token);
                                if (i==49) profile.MAX.DataTcpDownKB=atof(token);
                                if (i==50) profile.MIN.DataWwwUpKB=atof(token);
                                if (i==51) profile.MAX.DataWwwUpKB=atof(token);
                                if (i==52) profile.MIN.DataWwwDownKB=atof(token);
                                if (i==53) profile.MAX.DataWwwDownKB=atof(token);
                                if (i==54) profile.MIN.DataUdpUpKB=atof(token);
                                if (i==55) profile.MAX.DataUdpUpKB=atof(token);
                                if (i==56) profile.MIN.DataUdpDownKB=atof(token);
                                if (i==57) profile.MAX.DataUdpDownKB=atof(token);
                                if (i==58) profile.MIN.DataDnsUpKB=atof(token);
                                if (i==59) profile.MAX.DataDnsUpKB=atof(token);
                                if (i==60) profile.MIN.DataDnsDownKB=atof(token);
                                if (i==61) profile.MAX.DataDnsDownKB=atof(token);
                                token=strtok(NULL,seps);
                            }
                            check=1;
                            break;
                        }
                    }
                }
            }
        }
        fclose(fptr);
    }
    else
    {
        LogMessage("AnomalyDetection: Can't open Profile file.\n");
        check=0;
    }
}


/* Function: PreprocCleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting.
 *          Used to keep log file consistent.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this
 *                    functioin when it was registered, may be
 *                    needed to properly exit
 *
 * Returns: void function
 */

static void PreprocCleanExitFunction(int signal, void *data)
{
    LastLogTime += GatherTime;
    if(nlog)
    {
        SaveToLog(LastLogTime);
        time(&CurrentTime);
        LastLogTime = CompleteLog(LastLogTime,CurrentTime);
    }
}

//-------------------------------------------------------------------------
// printing stuff
//------------------------------------------------------------------------
static void PrintConf_AD (const AnomalydetectionConfig* pac)
{
    LogMessage("Anomaly Detecction config:\n");
    if(pac->LogPath != NULL)
        LogMessage("\t\tLOGPATH: %s\n",pac->LogPath);
    if(pac->ProfilePath != NULL)
        LogMessage("\t\tPROFILEPATH: %s\n",pac->ProfilePath);
    if(pac->nlog == 1)
        LogMessage("\t\tLOG: enable\n");
    else
        LogMessage("\t\tLOG: disable\n");
    if(pac->alert == 1)
        LogMessage("\t\tALERT: enable\n");
    else
        LogMessage("\t\tALERT: disable\n");
    LogMessage("\t\tGATHER TIME: %d\n",pac->GatherTime);

}

//-------------------------------------------------------------------------
// Funciones de INIT (estudiar en profundidad para checkear que ahcen en profundidad)
//-------------------------------------------------------------------------


/* Function: PreprocCleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting.
 *          Used to print stats screen.
 *
 * Arguments: exiting =>
 *
 * Returns: void function
 */
static void Preproc_FreeContext (AnomalydetectionConfig* pc)
{
    if ( pc )
        free(pc);
}

static int Preproc_FreePolicy(
        tSfPolicyUserContextId set,
        tSfPolicyId pid,
        void* pv
        )
{
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)pv;

    sfPolicyUserDataClear(set, pid);
    Preproc_FreeContext(pc);

    return 0;
}

static void Preproc_FreeSet (tSfPolicyUserContextId set)
{
    if ( !set )
        return;

    sfPolicyUserDataFreeIterate(set, Preproc_FreePolicy);
    sfPolicyConfigDelete(set);
}



static void AD_CleanExit(int signal, void* foo)
{
    LastLogTime += GatherTime;
    if(nlog)
    {
        SaveToLog(LastLogTime);
        time(&CurrentTime);
        LastLogTime = CompleteLog(LastLogTime,CurrentTime);
    }
    Preproc_FreeSet(anomalydetection_config);
}

static void AD_Reset (int signal, void *foo) { }

static void AD_PostConfigInit (struct _SnortConfig *sc, void *data)
{
    AnomalydetectionConfig *pPolicyConfig = (AnomalydetectionConfig *)sfPolicyUserDataGetDefault(anomalydetection_config) ;
    if ((  pPolicyConfig== NULL) ||
        (pPolicyConfig->LogPath == NULL))
    {
        return;
    }

     fptr = fopen(pPolicyConfig->LogPath, "a+");
    if (fptr == NULL)
    {
        FatalError("AnomalyDetection log file '%s' could not be opened: %s.\n",
                   pPolicyConfig->LogPath, strerror(errno));
    }
}

static int Preproc_CheckPolicy (
    struct _SnortConfig *sc,
    tSfPolicyUserContextId set,
    tSfPolicyId pid,
    void* pv)
{
    //NormalizerContext* pc = (NormalizerContext*)pv;
    return 0;
}

static int AD_CheckConfig (struct _SnortConfig *sc)
{
    int rval;

    if ( !anomalydetection_config )
        return 0;

    if ((rval = sfPolicyUserDataIterate(sc, anomalydetection_config, Preproc_CheckPolicy)))
        return rval;

    return 0;
}
static void AD_ResetStats(int signal, void *foo)
{
    return;
}


static void AD_PrintStats(int exiting)
{   
    tSfPolicyId pid = getNapRuntimePolicy();
    AnomalydetectionConfig* pac = (AnomalydetectionConfig*)sfPolicyUserDataGet(anomalydetection_config, pid);


    LogMessage("AnomalyDetection statistics:\n");
    LogMessage("           Overall packets: %llu\n",OverallF);
    LogMessage("     Other than IP packets: %llu\n",OtherCountF);
    LogMessage("     Number of TCP packets: %llu\n",TcpCountF);
    LogMessage("    Number of IP datagrams: %llu\n",IpCountF);
    LogMessage("   Number of UDP datagrams: %llu\n",UdpCountF);
    LogMessage("    Number of ICMP packets: %llu\n",IcmpCountF);
    LogMessage("     Number of ARP packets: %llu\n",ArpCountF);
    LogMessage("     Number of ARP request: %llu\n",ArpRequestF);
    LogMessage("       Number of ARP reply: %llu\n",ArpReplyF);
    if(ArpRequestF>ArpReplyF)
        LogMessage("                  ARP diff: %llu\n",ArpRequestF-ArpReplyF);
    else LogMessage("                  ARP diff: %llu\n",ArpReplyF-ArpRequestF);
    LogMessage("        Traffic in LAN TCP: %llu, UDP: %llu, ICMP: %llu\n",LanTcpF,LanUdpF,LanIcmpF);
    LogMessage("   Traffic loged in %s\n",pac->LogPath);
}



//------------------------------------------------------------
#ifdef SNORT_RELOAD
static void AnomalyDetectionReload(struct _SnortConfig *sc, char *args, void **new_config)
{
    // tSfPolicyUserContextId portscan_swap_config = (tSfPolicyUserContextId)*new_config;
    // tSfPolicyId policy_id = getParserPolicy(sc);
    // PortscanConfig *pPolicyConfig = NULL;

    // if (!portscan_swap_config)
    // {
    //     portscan_swap_config = sfPolicyConfigCreate();
    //     *new_config = (void *)portscan_swap_config;
    // }

    // if ((policy_id != 0) && (((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_swap_config)) == NULL))
    // {
    //     ParseError("Portscan: Must configure default policy if other "
    //                "policies are going to be configured.");
    // }


    // sfPolicyUserPolicySet (portscan_swap_config, policy_id);

    // pPolicyConfig = (PortscanConfig *)sfPolicyUserDataGetCurrent(portscan_swap_config);
    // if (pPolicyConfig)
    // {
    //     ParseError("Can only configure sfportscan once.\n");
    // }

    // pPolicyConfig = (PortscanConfig *)SnortAlloc(sizeof(PortscanConfig));
    // if (!pPolicyConfig)
    // {
    //     ParseError("SFPORTSCAN preprocessor: memory allocate failed.\n");
    // }


    // sfPolicyUserDataSetCurrent(portscan_swap_config, pPolicyConfig);
    // ParsePortscan(sc, pPolicyConfig, args);

    // if (policy_id != 0)
    // {
    //     pPolicyConfig->memcap = ((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_swap_config))->memcap;

    //     if (pPolicyConfig->logfile != NULL)
    //     {
    //         ParseError("Portscan:  logfile can only be configured in "
    //                    "default policy.\n");
    //     }
    // }

    // if ( !pPolicyConfig->disabled )
    // {
    //     AddFuncToPreprocList(sc, PortscanDetect, PRIORITY_SCANNER, PP_SFPORTSCAN,
    //                          PortscanGetProtoBits(pPolicyConfig->detect_scans));
    //     session_api->enable_preproc_all_ports( sc,
    //                                           PP_SFPORTSCAN, 
    //                                           PortscanGetProtoBits(pPolicyConfig->detect_scans) );
    // }
}

static int AnomalyDetectionReloadVerify(struct _SnortConfig *sc, void *swap_config)
{
    // tSfPolicyUserContextId portscan_swap_config = (tSfPolicyUserContextId)swap_config;
    // if ((portscan_swap_config == NULL) || (((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_swap_config)) == NULL) ||
    //     (portscan_config == NULL) || (((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_config)) == NULL))
    // {
    //     return 0;
    // }

    // if (((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_swap_config))->memcap != ((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_config))->memcap)
    // {
    //     return -1;
    // }

    // if ((((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_swap_config))->logfile != NULL) &&
    //     (((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_config))->logfile != NULL))
    // {
    //     if (strcasecmp(((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_swap_config))->logfile,
    //                    ((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_config))->logfile) != 0)
    //     {
    //         return -1;
    //     }
    // }
    // else if (((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_swap_config))->logfile != ((PortscanConfig *)sfPolicyUserDataGetDefault(portscan_config))->logfile)
    // {
    //     return -1;
    // }

    // return 0;
}

static void * AnomalyDetectionReloadSwap(struct _SnortConfig *sc, void  *swap_config)
{
    // tSfPolicyUserContextId portscan_swap_config = (tSfPolicyUserContextId)swap_config;
    // tSfPolicyUserContextId old_config = portscan_config;

    // if (portscan_swap_config == NULL)
    //     return NULL;

    // portscan_config = portscan_swap_config;

    // return (void *)old_config;
}

static void AnomalyDetectionReloadSwapFree(void *data)
{
    // if (data == NULL)
    //     return;

    // PortscanFreeConfigs((tSfPolicyUserContextId)data);
}
#endif






