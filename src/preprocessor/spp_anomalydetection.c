#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#define _GNU_SOURCE
#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <rpc/types.h>
#include <time.h>
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

#define CONF_SEPARATORS         " \t\n\r"


CGT_type *cgt, *cgt_old;
VGT_type *vgt;

FILE *fptr,*file2, *dataflow;
time_t LastLogTime, CurrentTime;
int countpaket;


int flag=0,check=1;

/************** Bloque de nuevas funciones y variables **************/

#ifdef PERF_PROFILING
PreprocStats ad_perf_stats;
#endif

/*puntero a la estructura tSfPolicyUserContext el cual contienen el id y el puntero a los archivos de configuracion*/
tSfPolicyUserContextId ad_context = NULL;

static void AD_CleanExit(int, void*);
static void AD_PrintStats(int);

/* Implementadas pero sin uso*/
static void AD_Reset(int, void*);   
static void AD_PostConfigInit(struct _SnortConfig *, void*);  
static int AD_CheckConfig (struct _SnortConfig *);
static void AD_ResetStats(int, void*);  


/************** Fin de funciones nuevas ****************************/
static void AnomalyDetectionInit(struct _SnortConfig *sc, char *args);
static void ParseAnomalyDetectionArgs(AnomalydetectionConfig*, char *);
static void PreprocFunction(Packet *, void *);
static void SaveToLog(time_t);
static void SavetoNetFlof(char *)
static void PrintConf_AD (const AnomalydetectionConfig*);

/************** RELOAD ****************************/
#ifdef SNORT_RELOAD
static void AnomalyDetectionReload(struct _SnortConfig *, char *, void **);
static int AnomalyDetectionReloadVerify(struct _SnortConfig *, void *);
static void * AnomalyDetectionReloadSwap(struct _SnortConfig *, void *);
static void AnomalyDetectionReloadSwapFree(void *);
#endif


/* Function: SetupAnomalyDetection( void )
 *
 * Purpose: funcion usada en plugbase.c para agregar las funciones necesarias para 
 *          para inicializar el preprocesar a Snort.
 *
 * Arguments: 
 *
 * Returns: void function
 */

void SetupAnomalyDetection(void)
{    
 #ifndef SNORT_RELOAD
     RegisterPreprocessor("AnomalyDetection", AnomalyDetectionInit);
 #else
     RegisterPreprocessor("AnomalyDetection", AnomalyDetectionInit, AnomalyDetectionReload,
                          NULL, AnomalyDetectionReloadSwap,
                          AnomalyDetectionReloadSwapFree);
#endif
    LogMessage("AnomalyDetection : AnomalyDetection is setup\n");

}



/* Function: AnomalyDetectionInit(struct _SnortConfig *sc, char *args)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments:   sc => ptr to SnortConfig
 *              args => ptr to argument string
 *
 * Returns: void function
 */

static void AnomalyDetectionInit(struct _SnortConfig *sc, char *args)
{
    LogMessage("AD-Init: AnomalyDetectionInit start.\n");
    
    int policy_id = (int) getParserPolicy(sc);
    AnomalydetectionConfig *ad_Config = NULL;

    if ( ad_context == NULL)
    {
        //create a new user context 
        ad_context = sfPolicyConfigCreate();
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Preprocessor: Anomaly Detection Initialized\n"););

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("anomalydetection", &ad_perf_stats, 0, &totalPerfStats);
#endif
        // borra punteros y espacios de memoria antes de cerrar
        AddFuncToPreprocCleanExitList(AD_CleanExit, NULL, PRIORITY_SCANNER, PP_SFPORTSCAN); 
        //imprime un informe cuando snort cierra
        RegisterPreprocStats("anomalydetection", AD_PrintStats); 

    }
    //fija policy_id al tSfPolicyUserContextId ad_context
    sfPolicyUserPolicySet(ad_context, policy_id);
    ad_Config = (AnomalydetectionConfig *)sfPolicyUserDataGetCurrent(ad_context);
    if (ad_Config)
    {
        ParseError("AnomalyDetection preprocessor can only be configured once.\n");
    }
    //asigna un espacio de memoria para la estructura AnomalydetectionConfig para agregarla al contexto
    ad_Config = (AnomalydetectionConfig* )SnortAlloc(sizeof(AnomalydetectionConfig)); 
    if (!ad_Config)
    {
        ParseError("AnomalyDetection preprocessor: memory allocate failed.\n");
    }
    //asigna la estructura de datos al conntexto
    sfPolicyUserDataSetCurrent(ad_context, ad_Config);

    /* Process argument list */
    ParseAnomalyDetectionArgs(ad_Config, args);
    /* Inicializa los grupos para almacenar sketches*/
    cgt = CGT_Init(ad_Config->groups,ad_Config->hashtest,ad_Config->lgn);
    vgt = VGT_Init(ad_Config->groups,ad_Config->hashtest,ad_Config->lgn);

    /* Agrega el preprocesar a una lista con prioridades al momento de acceder al dato bruto */
    AddFuncToPreprocList( sc, PreprocFunction, PRIORITY_SCANNER,  PP_SFPORTSCAN, PROTO_BIT__ALL);
    /* Agrega a la session_api para que el preprocesador reciba los paquetes desde la entrada */
    session_api->enable_preproc_all_ports( sc, PP_SFPORTSCAN, PROTO_BIT__ALL );

    countpaket = 0;
    dataflow = fopen('/var/log/snort/dataflow.txt',"a");


}

/* Function: ParseTemplateArgs(AnomalydetectionConfig* , char *)
 *
 * Purpose: Process the preprocessor arguements from the conf file and
 *          initialize the preprocessor's data struct.
 *
 * Arguments: 
 *      alert: 
 *      log:
 *      time:
 *      ProfilePath:
 *      LogPath:
 *      phi:
 *      epsilon:
 *      delta:
 * Returns: void function
 */

static void ParseAnomalyDetectionArgs(AnomalydetectionConfig* pc, char *args)
{
    int positionPath = 0;
    char * arg;
    char *pcEnd;
    char path[100];

    if ((args == NULL) || (pc == NULL))
        return;

    arg = strtok(args, CONF_SEPARATORS);

    while(arg != NULL)
    {
        if ( !strcasecmp("alert", arg) ) 
            pc->alert = 1;

        if ( !strcasecmp("log", arg) ) 
            pc->nlog = 1;

        if ( !strcasecmp("time", arg) ) 
        {
            arg = strtok(NULL, CONF_SEPARATORS);
            pc->GatherTime = (int) strtol(arg, &pcEnd, 10);
            if(pc->GatherTime < 1)
                pc->GatherTime = 1;
        }

        if ( !strcasecmp("LogPath", arg) ) {
            arg = strtok(NULL, CONF_SEPARATORS);
            strcpy(path,arg);
        }
        
        if ( !strcasecmp("phi", arg) ) {
            arg = strtok(NULL, CONF_SEPARATORS);
            pc->phi = atof(arg);
        }
           

        if ( !strcasecmp("epsilon", arg) ) 
        {
            arg = strtok(NULL, CONF_SEPARATORS);
            pc->epsilon = atof(arg);
            pc->groups = (int) ((2/pc->epsilon)+1);
        }

        if ( !strcasecmp("delta", arg) ) 
        {
            arg = strtok(NULL, CONF_SEPARATORS);
            pc->delta = atof(arg);
            pc->hashtest = (int) ((log10((double) 1/pc->delta)/log10(2))+1);
        }

        if ( !strcasecmp("lgn", arg) ){
           arg = strtok(NULL, CONF_SEPARATORS); 
           pc->lgn = (int) strtol(arg, &pcEnd, 10); 
        } 
           
       arg = strtok(NULL, CONF_SEPARATORS);
    }


    if(positionPath)
        sprintf(pc->LogPath, "%s/ADLog%d.txt", path, pc->GatherTime);
    else
        sprintf(pc->LogPath, "/var/log/snort/ADLog%d.txt", pc->GatherTime);

    PrintConf_AD(pc);
    if(pc->groups == 0 | pc->hashtest == 0)
            ParseError("Invalid preprocessor phi, epsilon or delta option");

}


/* Function: CGT(Packet *)
 *
 * Purpose:
 *         
 *
 * Arguments: 
 *
 * Returns: 
 */
static void addCGT(Packet *p)
{
    unsigned int ip;
    int packetsize;
    sfip_t *psrc;
    char iphs[INET_ADDRSTRLEN];
    char iphd[INET_ADDRSTRLEN];
    char * outputData;

    if(p->tcph!=NULL)
    {
        psrc = GET_SRC_IP(p);
        if(psrc->bits == 32){
            ip = (unsigned int) psrc->ip32[0];
            packetsize = 1;
            CGT_Update(cgt, ip, packetsize); 
            VGT_Update(vgt, ip, packetsize); 
        }
    }
       
        if(p->iph!= NULL){
            inet_ntop(AF_INET,&p->iph->ip_src,iphs,INET_ADDRSTRLEN);
            LogMessage("%s | ", iphs);
            inet_ntop(AF_INET,&p->iph->ip_dst,iphd,INET_ADDRSTRLEN);
            LogMessage("%s | ", iphd);
            LogMessage("%d | ", p->dsize);
            LogMessage("%u | ", p->sp);
            LogMessage("%u | ", p->dp); 
            LogMessage("%u | ",p->iph->ip_len);
            LogMessage("%u | ",p->pkth->pktlen);
            LogMessage("%u | ",p->iph->ip_proto);
            if(p->tcph != NULL){
                LogMessage("%u \n", p->tcph->th_flags);            
                sprintf(outputData,"%s | %s | %d | %u | %u | %u | %u | %u | %u \n",iphs, iphd, p->dsize, p->sp, p->dp, p->iph->ip_len, p->pkth->pktlen, p->iph->ip_proto, p->tcph->th_flags);
            }
            else{
                LogMessage("\n");
                sprintf(outputData,"%s | %s | %d | %u | %u | %u | %u | %u | \n",iphs, iphd, p->dsize, p->sp, p->dp, p->iph->ip_len, p->pkth->pktlen, p->iph->ip_proto);
            }
            
            
            SavetoNetFlof( outputData );
        }
            

   
            // p->iph                          //*IPHdr
            // p->orig_iph                     //*IPHdr
            // p->inner_iph                    //*IPHdr
            // p->outer_iph                    //*IPHdr
            // p->tcph                         //*TCPHdr
            // p->orig_tcph                    //*TCPHdr
            // p-dsize                           //uint16_t
            // p->sp                              //uint16_t
            // p->dp                         //uint16_t
            // p->orig_sp                       //uint16_t
            // p->orig_dp                       //uint16_t
            // p->application_protocol_ordinal  //int16_t
            // uint16_t max_dsize;
            // uint16_t ip_dsize; 
            // uint16_t alt_dsize;
            // const uint8_t *data;        /* packet payload pointer */
            // const uint8_t *ip_data;     /* IP payload pointer */ 
            // const TCPHdr *tcph, *orig_tcph;
            // const UDPHdr *udph, *orig_udph;
            // const UDPHdr *inner_udph;   /* if Teredo + UDP, this will be the inner UDP header */
            // const UDPHdr *outer_udph;   
            // (DAQ_PktHdr_t*)p->pkth)->pktlen 
}

static int compare(const void * a, const void * b)
{
  return (*(float*)a >= *(float*)b) ? 1 : -1;
}

/* Function: compare (const void * a, const void * b)
 *
 * Purpose:
 *         
 *
 * Arguments: 
 *
 * Returns: 
 */
static int ComputeThresh(CGT_type *cgt)
{
    tSfPolicyId pid = sfPolicyUserPolicyGet(ad_context);//getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);

    int ihash, jgroup, i, thresh;
    float count[pc->hashtest];

    for(ihash = 0; ihash < pc->hashtest; ihash++)
    {
        count[ihash] = 0;
        for(jgroup = 0; jgroup < pc->groups; jgroup++)
        {
            count[ihash] += cgt->counts[ihash*pc->hashtest+jgroup][0];
        }
    }

    qsort(count, pc->hashtest, sizeof(float), compare);
    thresh = (int) (pc->phi*count[(int)pc->hashtest/2]);
    LogMessage("#packet CGT.count: %d | Thresh: %d \n",cgt->count, thresh);
    return thresh;
}

static time_t increaseTime(time_t timec, int delta){
    struct tm* tm = localtime(&timec);
    tm->tm_sec += delta;
    return mktime(tm);
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
    //CGT_type *cgt_aux;
    tSfPolicyId pid =  sfPolicyUserPolicyGet(ad_context);//getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);
    unsigned int *outputList;
    double TimeInterval;

    int i;

    if(flag==0) //check if it is new file, all new log files need to have header
    {
        file2=fopen(pc->LogPath,"a");
        if ( file2 != NULL && ftell(file2) == 0 )
        {
            LogMessage("AnomalyDetection: Creating new log file in %s.\n",pc->LogPath);
            time( &LastLogTime );
            fprintf(file2,"hora,ip\n");
            time( &CurrentTime );
            LogMessage("%s",ctime(&CurrentTime));
            TimeInterval = difftime(CurrentTime,LastLogTime);
            while(TimeInterval > pc->GatherTime){
                time( &LastLogTime );
                TimeInterval = difftime(CurrentTime,LastLogTime);
            }   
        }else{
            LogMessage("AnomalyDetection: Opened an existing log file named AD%d.txt\n",pc->GatherTime);
            time( &LastLogTime );
        }
        fclose(file2);
        flag=1;
    }
    time( &CurrentTime );
    TimeInterval = difftime(CurrentTime,LastLogTime);

    if(TimeInterval >= pc->GatherTime)
    {
        LastLogTime = increaseTime(LastLogTime, pc->GatherTime);

        if (pc->nlog) //if flag "log" is set in config file, preprocessor will log stats to file
        {
            SaveToLog(LastLogTime); //save in the log file the current count data
     
            LogMessage("AnomalyDetection log time:  %s",ctime(&LastLogTime));
            LogMessage("\nPaquetes capturados por SNORT: %d\n",countpaket);
            outputList = CGT_Output(cgt, vgt, ComputeThresh(cgt));
            for(i=1; i <= outputList[0]; i++)
            {
                LogMessage("CANDIDATO ==> %u.%u.%u.%u\n" ,(outputList[i] & 0x000000ff),(outputList[i] & 0x0000ff00) >> 8,(outputList[i] & 0x00ff0000) >> 16,(outputList[i] & 0xff000000) >> 24);
            }
            //cgt_aux = cgt_old;
            //cgt_old = cgt;
            //CGT_Destroy(cgt_aux);
            CGT_Destroy(cgt);
            VGT_Destroy(vgt);
            cgt = CGT_Init(pc->groups,pc->hashtest,pc->lgn);
            vgt = VGT_Init(pc->groups,pc->hashtest,pc->lgn);
        }
     
        if (pc->alert)  //if flag "alert" is set in config file, preprocessor will generate alerts
        {
            if(check)
            {
                //if (profile.MAX.DataDnsDownKB<DataDnsDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED");
            }
        }
        // PREPROC_PROFILE_START(ad_perf_stats);
        addCGT(p); //agrega el nuevo paquete a la estructura
        // PREPROC_PROFILE_END(ad_perf_stats);
        countpaket=0;

    }
    else{
        addCGT(p);
        countpaket++;

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
static void SavetoNetFlof(char * data){
    if(data != NULL)
        fprintf(dataflow,"%s", &data);

}
static void SaveToLog(time_t LastLogTime)
{
    tSfPolicyId pid = getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);

    // char TimeStamp[30];
    // struct tm *tmp;
    // tmp = localtime(&LastLogTime);
    // strftime(TimeStamp,sizeof(TimeStamp),"%d-%m-%y,%T,%a", tmp);
    file2=fopen(pc->LogPath,"a");
    //fprintf(file2,"%s,%d,%llu\n", TimeStamp,pc->GatherTime,TcpCountFp);
    fprintf(file2,"%s", ctime(&LastLogTime));
    fclose(file2);
}



//-------------------------------------------------------------------------
// printing stuff
//------------------------------------------------------------------------
static void PrintConf_AD (const AnomalydetectionConfig* pac)
{
    LogMessage("Anomaly Detecction config:\n");
    if(pac->LogPath != NULL)
        LogMessage("\t\tLOGPATH: %s\n",pac->LogPath);
    if(pac->nlog == 1)
        LogMessage("\t\tLOG: enable\n");
    else
        LogMessage("\t\tLOG: disable\n");
    if(pac->alert == 1)
        LogMessage("\t\tALERT: enable\n");
    else
        LogMessage("\t\tALERT: disable\n");
    LogMessage("\t\tGATHER TIME: %d\n",pac->GatherTime);
    LogMessage("\t\tphi: %f\n",pac->phi);
    LogMessage("\t\tepsilon: %f\n",pac->epsilon);
    LogMessage("\t\tdelta: %f\n",pac->delta);
    LogMessage("\t\tgroups: %d\n",pac->groups);
    LogMessage("\t\thashtest: %d\n",pac->hashtest);

}

//-------------------------------------------------------------------------
// Funciones de INIT (estudiar en profundidad para checkear que ahcen en profundidad)
//-------------------------------------------------------------------------


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
    tSfPolicyId pid = getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);

    LastLogTime += pc->GatherTime;
    if(pc->nlog)
    {
        //implementación de cosas que hacer antes de que snort se cierre
    }
    Preproc_FreeSet(ad_context);
    fclose(dataflow);

}

static void AD_Reset (int signal, void *foo) { }

static void AD_PostConfigInit (struct _SnortConfig *sc, void *data)
{
    AnomalydetectionConfig *ad_Config = (AnomalydetectionConfig *)sfPolicyUserDataGetDefault(ad_context) ;
    if ((  ad_Config== NULL) ||
        (ad_Config->LogPath == NULL))
    {
        return;
    }

     fptr = fopen(ad_Config->LogPath, "a+");
    if (fptr == NULL)
    {
        FatalError("AnomalyDetection log file '%s' could not be opened: %s.\n",
                   ad_Config->LogPath, strerror(errno));
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

    if ( !ad_context )
        return 0;

    if ((rval = sfPolicyUserDataIterate(sc, ad_context, Preproc_CheckPolicy)))
        return rval;

    return 0;
}
static void AD_ResetStats(int signal, void *foo)
{
    return;
}


static void AD_PrintStats(int exiting)
{   
    // tSfPolicyId pid = getNapRuntimePolicy();
    // AnomalydetectionConfig* pac = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);


    // LogMessage("AnomalyDetection statistics:\n");
    // LogMessage("           Overall packets: %llu\n",OverallF);
    // LogMessage("     Other than IP packets: %llu\n",OtherCountF);
    // LogMessage("     Number of TCP packets: %llu\n",TcpCountF);
    // LogMessage("    Number of IP datagrams: %llu\n",IpCountF);
    // LogMessage("   Number of UDP datagrams: %llu\n",UdpCountF);
    // LogMessage("    Number of ICMP packets: %llu\n",IcmpCountF);
    // LogMessage("     Number of ARP packets: %llu\n",ArpCountF);
    // LogMessage("     Number of ARP request: %llu\n",ArpRequestF);
    // LogMessage("       Number of ARP reply: %llu\n",ArpReplyF);
    // if(ArpRequestF>ArpReplyF)
    //     LogMessage("                  ARP diff: %llu\n",ArpRequestF-ArpReplyF);
    // else LogMessage("                  ARP diff: %llu\n",ArpReplyF-ArpRequestF);
    // LogMessage("        Traffic in LAN TCP: %llu, UDP: %llu, ICMP: %llu\n",LanTcpF,LanUdpF,LanIcmpF);
    // LogMessage("   Traffic loged in %s\n",pac->LogPath);
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






