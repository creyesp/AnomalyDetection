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

CGT_type *cgtIPSD_PSD, *cgtIPSD_PSD_old;
VGT_type *vgtIPSD_PSD, *vgtIPSD_PSD_old;
CGT_type *cgtIPSD_PD, *cgtIPSD_PD_old;
VGT_type *vgtIPSD_PD, *vgtIPSD_PD_old;
CGT_type *cgtIPSD_PS, *cgtIPSD_PS_old;
VGT_type *vgtIPSD_PS, *vgtIPSD_PS_old;
CGT_type *cgtIPS, *cgt_oldIPS;
VGT_type *vgtIPS, *vgt_oldIPS;
CGT_type *cgtIPD, *cgt_oldIPD;
VGT_type *vgtIPD, *vgt_oldIPD;
CGT_type *cgtIPSD, *cgt_oldIPSD;
VGT_type *vgtIPSD, *vgt_oldIPSD;

FILE *dataflow;
FILE *outputIPsdPORTsd, *outputIPsdPORTs, *outputIPsdPORTd, *outputIPsd, 
     *outputIPs, *outputIPd;
FILE *outputIPsdPORTsd_diff, *outputIPsdPORTs_diff, *outputIPsdPORTd_diff, *outputIPsd_diff, 
     *outputIPs_diff, *outputIPd_diff;

time_t LastLogTime, CurrentTime;
int countpaket;


/************** Bloque de nuevas funciones y variables **************/
#ifdef PERF_PROFILING
PreprocStats ad_perf_stats;
#endif

/*puntero a la estructura tSfPolicyUserContext el cual contienen el id y el puntero a los archivos de configuracion*/
tSfPolicyUserContextId ad_context = NULL;

static void loadFile(FILE **, char *, char *);
static int compare(const void * , const void * );
static time_t increaseTime(time_t , int );

/* Implementadas pero sin uso*/
static void AD_Reset(int, void*);   
static void AD_PostConfigInit(struct _SnortConfig *, void*);  
static int AD_CheckConfig (struct _SnortConfig *);
static void AD_ResetStats(int, void*);  

/************** Basic function preprocessor SNORT  ****************************/
static void AnomalyDetectionInit(struct _SnortConfig *sc, char *args);
static void ParseAnomalyDetectionArgs(AnomalydetectionConfig*, char *);
static void PreprocFunction(Packet *, void *);
static void preprocFreeOutputList( unsigned int **);
static void PrintConf_AD (const AnomalydetectionConfig*);
static void AD_PrintStats(int);
static void AD_CleanExit(int, void*);
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
    int policy_id = (int) getParserPolicy(sc);
    AnomalydetectionConfig *ad_Config = NULL;

    if ( ad_context == NULL)
    {
        /* Create a new user context */
        ad_context = sfPolicyConfigCreate();

#ifdef PERF_PROFILING
        RegisterPreprocessorProfile("anomalydetection", &ad_perf_stats, 0, &totalPerfStats);
#endif
        /* Free memory allocate for struct pointer and pointer file before exit. */
        AddFuncToPreprocCleanExitList(AD_CleanExit, NULL, PRIORITY_SCANNER, PP_SFPORTSCAN); 
        /* Print summarization of preprocessor before exit. */
        RegisterPreprocStats("anomalydetection", AD_PrintStats); 
    }

    /* Set policy_id to tSfPolicyUserContextId ad_context */
    sfPolicyUserPolicySet(ad_context, policy_id);
    ad_Config = (AnomalydetectionConfig *)sfPolicyUserDataGetCurrent(ad_context);
    if (ad_Config)
    {
        ParseError("AnomalyDetection preprocessor can only be configured once.\n");
    }
    /* Memory allocate for AnomalydetectionConfig struct */
    ad_Config = (AnomalydetectionConfig* )SnortAlloc(sizeof(AnomalydetectionConfig)); 
    if (!ad_Config)
    {
        ParseError("AnomalyDetection preprocessor: memory allocate failed.\n");
    }
    sfPolicyUserDataSetCurrent(ad_context, ad_Config);

    /* Process argument list */
    ParseAnomalyDetectionArgs(ad_Config, args);
    
    /* Initialization Group Tests */
    CGT_Init(&cgtIPSD_PSD, ad_Config->groups,ad_Config->hashtest,96);
    CGT_Init(&cgtIPSD_PS, ad_Config->groups,ad_Config->hashtest,96);
    CGT_Init(&cgtIPSD_PD, ad_Config->groups,ad_Config->hashtest,96);
    CGT_Init(&cgtIPSD, ad_Config->groups,ad_Config->hashtest,64);
    CGT_Init(&cgtIPS, ad_Config->groups,ad_Config->hashtest,32);
    CGT_Init(&cgtIPD, ad_Config->groups,ad_Config->hashtest,32);

    CGT_Init(&cgtIPSD_PSD_old, ad_Config->groups,ad_Config->hashtest,96);    
    CGT_Init(&cgtIPSD_PS_old, ad_Config->groups,ad_Config->hashtest,96);
    CGT_Init(&cgtIPSD_PD_old, ad_Config->groups,ad_Config->hashtest,96);
    CGT_Init(&cgt_oldIPSD, ad_Config->groups,ad_Config->hashtest,64);
    CGT_Init(&cgt_oldIPS, ad_Config->groups,ad_Config->hashtest,32);
    CGT_Init(&cgt_oldIPD, ad_Config->groups,ad_Config->hashtest,32);
    
   /* Initialization Group Tests for verifitation */
    VGT_Init(&vgtIPSD_PSD, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgtIPSD_PS, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgtIPSD_PD, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgtIPSD, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgtIPS, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgtIPD, ad_Config->groups,ad_Config->hashtest);

    VGT_Init(&vgtIPSD_PSD_old, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgtIPSD_PS_old, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgtIPSD_PD_old, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgt_oldIPSD, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgt_oldIPS, ad_Config->groups,ad_Config->hashtest);
    VGT_Init(&vgt_oldIPD, ad_Config->groups,ad_Config->hashtest);

    /* Append the PreprocFunction to priority list for access the raw data */
    AddFuncToPreprocList( sc, PreprocFunction, PRIORITY_SCANNER,  PP_SFPORTSCAN, PROTO_BIT__ALL);
    /* Append the current preprocessor to session_api for get the packets */
    session_api->enable_preproc_all_ports( sc, PP_SFPORTSCAN, PROTO_BIT__ALL );

    countpaket = 0;
    if(ad_Config->datah){
        loadFile(&dataflow, ad_Config->LogPath , "dataflow.csv");
        if ( dataflow != NULL && ftell(dataflow) == 0 )
        {
            LogMessage("AnomalyDetection: Creating new DATAFLOW file\n");
            fprintf(dataflow,"DATE,IP_SRC,IP_DST,PORT_SRC,PORT_DST,DSIZE,PKLEN,IP_LEN,IP_PROTO,TH_FLAG\n");   
        }else
            LogMessage("AnomalyDetection: Opened an existing DATAFLOW\n");
    }

    loadFile(&outputIPsdPORTsd_diff, ad_Config->LogPath , "IPsdPORTsd.csv");
    loadFile(&outputIPsdPORTs_diff, ad_Config->LogPath , "IPsdPORTs.csv");
    loadFile(&outputIPsdPORTd_diff, ad_Config->LogPath , "IPsdPORTd.csv");
    loadFile(&outputIPsd_diff, ad_Config->LogPath , "IPsd.csv");
    loadFile(&outputIPs_diff, ad_Config->LogPath , "IPs.csv");
    loadFile(&outputIPd_diff, ad_Config->LogPath , "IPd.csv");

    if ( outputIPsdPORTsd_diff == NULL ||
        outputIPsdPORTs_diff == NULL || outputIPsdPORTd_diff == NULL || outputIPsd_diff == NULL ||
        outputIPs_diff == NULL || outputIPd_diff == NULL)
        FatalError("AnomalyDetection log file could not be opened.\n");
    else 
        LogMessage("AnomalyDetection: Logs files opened.\n");

    time( &LastLogTime );
    


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
 *      verbose: 
 * Returns: void function
 */

static void ParseAnomalyDetectionArgs(AnomalydetectionConfig* pc, char *args)
{
    char * arg;
    char *pcEnd;

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
            if( *arg && arg[strlen(arg) - 1] == '/')
                sprintf(pc->LogPath, "%s", arg);
            else
                sprintf(pc->LogPath, "%s/", arg);
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

        if ( !strcasecmp("verbose", arg) ) 
        {
            pc->verbose = 1;
        }

        if ( !strcasecmp("datah", arg) ) 
        {
            pc->datah = 1;
        }

        if ( !strcasecmp("alertThresh", arg) ) 
        {
            pc->alertThresh = atoi(arg);
        }

           
       arg = strtok(NULL, CONF_SEPARATORS);
    }

    PrintConf_AD(pc);
    if(pc->groups == 0 || pc->hashtest == 0)
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
static void addGT( Packet *p)
{

    tSfPolicyId pid = sfPolicyUserPolicyGet(ad_context);//getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);

    unsigned int ipsrc,ipdst;
    unsigned short int srcport, dstport;
    int packetsize;
    sfip_t *psrc;
    char iphs[INET_ADDRSTRLEN];
    char iphd[INET_ADDRSTRLEN];

    time_t timestampDF;
    struct tm* tmlocal;
    char strdate[200];

    if(p->tcph!=NULL)
    {
        psrc = GET_SRC_IP(p);
        if(psrc->bits == 32){
            ipsrc = p->iph->ip_src.s_addr ;
            ipdst = p->iph->ip_dst.s_addr ;
            srcport = (unsigned short int)p->sp;
            dstport = (unsigned short int)p->dp;
            packetsize = 1;
            CGT_Update96(cgtIPSD_PSD, ipsrc,ipdst, srcport, dstport, packetsize,(int)p->dsize);
            CGT_Update96(cgtIPSD_PSD_old, ipsrc,ipdst, srcport, dstport, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update96(vgtIPSD_PSD, ipsrc,ipdst, srcport, dstport, packetsize); 
            VGT_Update96(vgtIPSD_PSD_old, ipsrc,ipdst, srcport, dstport, -1*packetsize); 

            CGT_Update96(cgtIPSD_PS, ipsrc,ipdst, srcport, 0, packetsize,(int)p->dsize);
            CGT_Update96(cgtIPSD_PS_old, ipsrc,ipdst, srcport, 0, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update96(vgtIPSD_PS, ipsrc,ipdst, srcport, 0, packetsize); 
            VGT_Update96(vgtIPSD_PS_old, ipsrc,ipdst, srcport, 0, -1*packetsize);   

            CGT_Update96(cgtIPSD_PD, ipsrc,ipdst, 0, dstport, packetsize,(int)p->dsize);
            CGT_Update96(cgtIPSD_PD_old, ipsrc,ipdst, 0, dstport, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update96(vgtIPSD_PD, ipsrc,ipdst, 0, dstport, packetsize); 
            VGT_Update96(vgtIPSD_PD_old, ipsrc,ipdst, 0, dstport, -1*packetsize);   

            CGT_Update64(cgtIPSD, ipsrc,ipdst, packetsize,(int)p->dsize);
            CGT_Update64(cgt_oldIPSD, ipsrc,ipdst, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update64(vgtIPSD, ipsrc,ipdst, packetsize); 
            VGT_Update64(vgt_oldIPSD, ipsrc,ipdst, -1*packetsize);

            CGT_Update(cgtIPS, ipsrc, packetsize,(int)p->dsize);
            CGT_Update(cgt_oldIPS, ipsrc, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update(vgtIPS, ipsrc, packetsize); 
            VGT_Update(vgt_oldIPS, ipsrc, -1*packetsize);                    

            CGT_Update(cgtIPD, ipdst, packetsize,(int)p->dsize);
            CGT_Update(cgt_oldIPD, ipdst, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update(vgtIPD, ipdst, packetsize); 
            VGT_Update(vgt_oldIPD, ipdst, -1*packetsize);  

        }
    }
       
        if(p->iph!= NULL && pc->datah)
        {
            inet_ntop(AF_INET,&p->iph->ip_src,iphs,INET_ADDRSTRLEN);
            inet_ntop(AF_INET,&p->iph->ip_dst,iphd,INET_ADDRSTRLEN);
            time( &timestampDF );
            tmlocal = localtime(&timestampDF);
            strftime(strdate, 200, "\"%x %X\"", tmlocal);


            if(p->tcph != NULL)
                fprintf(dataflow,"%s,\"%s\",\"%s\",%u,%u,%u,%u,%u,%u,%u\n",strdate, iphs, iphd, p->sp, p->dp, p->dsize, p->pkth->pktlen, p->iph->ip_len, p->iph->ip_proto, p->tcph->th_flags);
            else
                fprintf(dataflow,"%s,\"%s\",\"%s\",%u,%u,%u,%u,%u,%u,-1\n",strdate, iphs, iphd, p->sp, p->dp, p->dsize, p->pkth->pktlen, p->iph->ip_len, p->iph->ip_proto);            
        }

   
            // p->iph                          //*IPHdr
            // p->orig_iph                     //*IPHdr
            // p->inner_iph                    //*IPHdr
            // p->outer_iph                    //*IPHdr
            // p->tcph                         //*TCPHdr
            // p->orig_tcph                    //*TCPHdr
            // p-dsize                           //uint16_t bytes
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


static int ComputeDiffThresh(const CGT_type *cgt)
{
    tSfPolicyId pid = sfPolicyUserPolicyGet(ad_context);//getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);

    int ihash, jgroup;
    int count[cgt->tests], thresh;
    for(ihash = 0; ihash < cgt->tests; ihash++)
    {
        count[ihash] = 0;
        for(jgroup = 0; jgroup < cgt->buckets; jgroup++)
        {   
            count[ihash] += abs(cgt->counts[ihash*cgt->buckets+jgroup][0]);
        }
    }
    qsort(count, cgt->tests, sizeof(int), compare);
    thresh =  (int)(pc->phi*count[(int)cgt->tests/2]);
    if(pc->verbose) LogMessage("#packet CGT.count: %d | Thresh DIFF: %d \n",count[(int)cgt->tests/2], thresh);
    return ( (thresh > 0)? thresh:1 );
}



/* Function: writeOutput( FILE* outputfile, unsigned int ** outputList )
 *
 * Purpose: 
 *
 * Arguments: 
 *
 * Returns: 
 */

void writeOutput( FILE* outputfile, unsigned int ** outputList , char tsName[])
{
    tSfPolicyId pid = sfPolicyUserPolicyGet(ad_context);//getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);
    
    struct tm* tmlocal;
    char strdate[200], msg[200];
    int i;
    
    if(pc->verbose) LogMessage("=================   %s  =================  \n",tsName);
    if ( outputfile != NULL)
    {
        if(outputList != NULL)
        {
            tmlocal = localtime(&LastLogTime);
            strftime(strdate, 200, "\"%x %X\"", tmlocal);
            if(outputList[0][1] == 3){
                for(i=1; i < outputList[0][0]; i++)
                {
                    if(pc->verbose)
                    {
                        LogMessage("| IP %u.%u.%u.%u\t", outputList[i][0]&0x000000ff,(outputList[i][0]&0x0000ff00)>>8,(outputList[i][0]&0x00ff0000)>>16,(outputList[i][0]&0xff000000)>>24);
                        LogMessage("| packets: %10d \t| size: %10d |\n", outputList[i][1],outputList[i][2]);                        
                    }
                    fprintf(outputfile,"%s," ,strdate);
                    fprintf(outputfile,"\"%u.%u.%u.%u\",",(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24);
                    fprintf(outputfile,"%d,%d,%d\n",outputList[i][1], abs(outputList[i][1]), outputList[i][2]);
                    if (pc->alert)  //if flag "alert" is set in config file, preprocessor will generate alerts
                    {
                        LogMessage("ALERT IPsrc IPdst!\n");
                        //if (profile.MAX.DataDnsDownKB<DataDnsDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED");
                        if(outputList[i][3] > pc->alertThresh )
                        {
                            sprintf(msg,"ANOMALY DETECTION %s: %u.%u.%u.%u PACKETS: %d BYTES: %d",tsName,(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24, outputList[i][1], outputList[i][2])
                            GenerateSnortEventOtn(GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_IP_PACKETS,1,999,1,msg);
                        }
                    }
                }
            }else if(outputList[0][1] == 4){
                for(i=1; i < outputList[0][0]; i++)
                {
                    if(pc->verbose)
                    {   
                        LogMessage("| IPs %u.%u.%u.%u\t" ,(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24);
                        LogMessage("| IPd %u.%u.%u.%u \t" ,(outputList[i][1] & 0x000000ff),(outputList[i][1] & 0x0000ff00) >> 8,(outputList[i][1] & 0x00ff0000) >> 16,(outputList[i][1] & 0xff000000) >> 24);
                        LogMessage("| packet: %10d | size: %10d |\n",outputList[i][2], outputList[i][3]);
                    }
                    fprintf(outputfile,"%s," ,strdate);
                    fprintf(outputfile,"\"%u.%u.%u.%u\",",(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24);
                    fprintf(outputfile,"\"%u.%u.%u.%u\",",(outputList[i][1] & 0x000000ff),(outputList[i][1] & 0x0000ff00) >> 8,(outputList[i][1] & 0x00ff0000) >> 16,(outputList[i][1] & 0xff000000) >> 24);
                    fprintf(outputfile,"%d,%d,%d\n",outputList[i][2],abs(outputList[i][2]), outputList[i][3]);
                    if (pc->alert)  //if flag "alert" is set in config file, preprocessor will generate alerts
                    {
                        LogMessage("ALERT IPsrc IPdst!\n");
                        //if (profile.MAX.DataDnsDownKB<DataDnsDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED");
                        if(outputList[i][3] > pc->alertThresh )
                        {
                            sprintf(msg,"ANOMALY DETECTION IPsrc: %u.%u.%u.%u IPdst: %u.%u.%u.%u PACKETS: %d BYTES: %d",(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24, (outputList[i][1] & 0x000000ff),(outputList[i][1] & 0x0000ff00) >> 8,(outputList[i][1] & 0x00ff0000) >> 16,(outputList[i][1] & 0xff000000) >> 24, outputList[i][2], outputList[i][3])
                            GenerateSnortEventOtn(GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_IPSD_PACKETS,1,999,1,msg);
                        }
                    }
                }
            }else if (outputList[0][1] == 5)
            {
                for(i=1; i < outputList[0][0]; i++)
                {
                    if(pc->verbose)
                    {   
                        LogMessage("| IPs %u.%u.%u.%u\t" ,(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24);
                        LogMessage("| IPd %u.%u.%u.%u\t" ,(outputList[i][1] & 0x000000ff),(outputList[i][1] & 0x0000ff00) >> 8,(outputList[i][1] & 0x00ff0000) >> 16,(outputList[i][1] & 0xff000000) >> 24);
                        LogMessage("| PORTs: %5u PORTd: %5u | packet: %10d | size: %10d |\n", (outputList[i][2]>>16), ((outputList[i][2]<<16)>>16),outputList[i][3], outputList[i][4]);
                    }
                    fprintf(outputfile,"%s," ,strdate);
                    fprintf(outputfile,"\"%u.%u.%u.%u\",",(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24);
                    fprintf(outputfile,"\"%u.%u.%u.%u\",",(outputList[i][1] & 0x000000ff),(outputList[i][1] & 0x0000ff00) >> 8,(outputList[i][1] & 0x00ff0000) >> 16,(outputList[i][1] & 0xff000000) >> 24);
                    fprintf(outputfile,"%u,%u,%d,%d,%d\n",(outputList[i][2]>>16), ((outputList[i][2]<<16)>>16),outputList[i][3],abs(outputList[i][3]), outputList[i][4]);
                    if (pc->alert)  //if flag "alert" is set in config file, preprocessor will generate alerts
                    {
                        LogMessage("ALERT IPsrc IPdst PORTsrc PORTdst!\n");
                        //if (profile.MAX.DataDnsDownKB<DataDnsDownKB/TimeInterval) GenerateSnortEvent(p,GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED,1,999,1,"AD_HIGH_VALUE_OF_DOWNLOAD_DNS_DATA_SPEED");
                        if(outputList[i][3] > pc->alertThresh )
                        {
                            sprintf(msg,"ANOMALY DETECTION IPsrc: %u.%u.%u.%u IPdst: %u.%u.%u.%u PORTsrc: %u PORTdst: %u PACKETS: %d BYTES: %d",(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24, (outputList[i][1] & 0x000000ff),(outputList[i][1] & 0x0000ff00) >> 8,(outputList[i][1] & 0x00ff0000) >> 16,(outputList[i][1] & 0xff000000) >> 24, (outputList[i][2]>>16), ((outputList[i][2]<<16)>>16),outputList[i][3], outputList[i][4])
                            GenerateSnortEventOtn(GENERATOR_SPP_AD,AD_HIGH_VALUE_OF_IPSD_PORTSD_PACKETS,1,999,1,msg);
                        }
                    }
                }                
            }
        }else
            if(pc->verbose) LogMessage("Lista NULL\n");
    }else
        if(pc->verbose) LogMessage("File NULL\n");
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
    tSfPolicyId pid =  sfPolicyUserPolicyGet(ad_context);//getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);
    unsigned int ** diffList_IPsdPORTsd, ** diffList_IPsdPORTs, ** diffList_IPsdPORTd, **diffList_IPs, **diffList_IPd, **diffList_IPsd;
    double TimeInterval;


    time( &CurrentTime );
    TimeInterval = difftime(CurrentTime,LastLogTime);
    if(TimeInterval >= pc->GatherTime)
    {   
        LastLogTime = increaseTime(LastLogTime, pc->GatherTime);

        if (pc->nlog) //if flag "log" is set in config file, preprocessor will log stats to file
        {
            if(pc->verbose)
            {
                LogMessage("\n************************************************************************\n");
                LogMessage("AnomalyDetection log time:  %s",ctime(&LastLogTime));
                LogMessage("Paquetes capturados por SNORT: %d\n",countpaket);
                LogMessage("\n************************************************************************\n");
            }
            
            CGT_Output96(&diffList_IPsdPORTsd, cgtIPSD_PSD, vgtIPSD_PSD, ComputeDiffThresh(cgtIPSD_PSD));
            writeOutput(outputIPsdPORTsd_diff,diffList_IPsdPORTsd, "IPsrc/dst PORTsrc/dst");

            CGT_Destroy(cgtIPSD_PSD);
            VGT_Destroy(vgtIPSD_PSD);
            cgtIPSD_PSD = cgtIPSD_PSD_old;
            vgtIPSD_PSD = vgtIPSD_PSD_old;
            CGT_Init(&cgtIPSD_PSD_old, pc->groups,pc->hashtest,96);
            VGT_Init(&vgtIPSD_PSD_old, pc->groups,pc->hashtest);            

            if(diffList_IPsdPORTsd != NULL) preprocFreeOutputList(diffList_IPsdPORTsd);
            
            CGT_Output96(&diffList_IPsdPORTs, cgtIPSD_PS, vgtIPSD_PS, ComputeDiffThresh(cgtIPSD_PS)) ;
            writeOutput(outputIPsdPORTs_diff,diffList_IPsdPORTs,"Psrc/dst - PORTsrc");
            
            CGT_Destroy(cgtIPSD_PS);
            VGT_Destroy(vgtIPSD_PS);
            cgtIPSD_PS = cgtIPSD_PS_old;
            vgtIPSD_PS = vgtIPSD_PS_old;
            CGT_Init(&cgtIPSD_PS_old, pc->groups,pc->hashtest,96);
            VGT_Init(&vgtIPSD_PS_old, pc->groups,pc->hashtest);

            if(diffList_IPsdPORTs != NULL) preprocFreeOutputList(diffList_IPsdPORTs);
            
            CGT_Output96(&diffList_IPsdPORTd, cgtIPSD_PD, vgtIPSD_PD, ComputeDiffThresh(cgtIPSD_PD));    
            writeOutput(outputIPsdPORTd_diff,diffList_IPsdPORTd, "IPsrc/dst - PORTdst");
            
            CGT_Destroy(cgtIPSD_PD);
            VGT_Destroy(vgtIPSD_PD);
            cgtIPSD_PD = cgtIPSD_PD_old;
            vgtIPSD_PD = vgtIPSD_PD_old;
            CGT_Init(&cgtIPSD_PD_old, pc->groups,pc->hashtest,96);
            VGT_Init(&vgtIPSD_PD_old, pc->groups,pc->hashtest);
           
            if(diffList_IPsdPORTd != NULL) preprocFreeOutputList(diffList_IPsdPORTd);     
            
            CGT_Output64(&diffList_IPsd, cgtIPSD, vgtIPSD, ComputeDiffThresh(cgtIPSD));
            writeOutput(outputIPsd_diff,diffList_IPsd, "IPsrc/dst");
            
            CGT_Destroy(cgtIPSD);
            VGT_Destroy(vgtIPSD);
            cgtIPSD = cgt_oldIPSD;
            vgtIPSD = vgt_oldIPSD;
            CGT_Init(&cgt_oldIPSD, pc->groups,pc->hashtest,64);
            VGT_Init(&vgt_oldIPSD, pc->groups,pc->hashtest);

            if(diffList_IPsd != NULL) preprocFreeOutputList(diffList_IPsd);
            
            CGT_Output(&diffList_IPs, cgtIPS, vgtIPS, ComputeDiffThresh(cgtIPS));
            writeOutput(outputIPs_diff,diffList_IPs, "IPsrc");            
            
            CGT_Destroy(cgtIPS);
            VGT_Destroy(vgtIPS);
            cgtIPS = cgt_oldIPS;
            vgtIPS = vgt_oldIPS;
            CGT_Init(&cgt_oldIPS, pc->groups,pc->hashtest,32);
            VGT_Init(&vgt_oldIPS, pc->groups,pc->hashtest);
    
            if(diffList_IPs != NULL) preprocFreeOutputList(diffList_IPs);        
                        
            CGT_Output(&diffList_IPd, cgtIPD, vgtIPD, ComputeDiffThresh(cgtIPD));
            writeOutput(outputIPd_diff,diffList_IPd, "IPdst");            
            
            CGT_Destroy(cgtIPD);
            VGT_Destroy(vgtIPD);
            cgtIPD = cgt_oldIPD;
            vgtIPD = vgt_oldIPD;
            CGT_Init(&cgt_oldIPD, pc->groups,pc->hashtest,32);
            VGT_Init(&vgt_oldIPD, pc->groups,pc->hashtest);
    
            if(diffList_IPd != NULL) preprocFreeOutputList(diffList_IPd); 
        }
     

        // PREPROC_PROFILE_START(ad_perf_stats);
        addGT(p); //agrega el nuevo paquete a la estructura
        // PREPROC_PROFILE_END(ad_perf_stats);
        countpaket=0;
    }
    else{
        countpaket++;
        addGT(p);
    } 
}


static void preprocFreeOutputList( unsigned int ** outputList)
{
    int i,nlist;
    /* The length of outputList is nlist */
    nlist = **outputList;
    for(i = 0   ; i < nlist; i++){ 
        free(outputList[i]);
        outputList[i] = NULL;
    }

    free(outputList); 
    outputList = NULL;
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
    if(pac->verbose == 1)     
        LogMessage("\t\tVerbose: enable\n");
    else
        LogMessage("\t\tVerbose: disable\n");
    if(pac->datah == 1)     
        LogMessage("\t\tsave DataH: enable\n");
    else
        LogMessage("\t\tsave DataH: disable\n");
    
    LogMessage("\t\tGATHER TIME: %d\n",pac->GatherTime);
    LogMessage("\t\tphi: %f\n",pac->phi);
    LogMessage("\t\tepsilon: %f\n",pac->epsilon);
    LogMessage("\t\tdelta: %f\n",pac->delta);
    LogMessage("\t\tgroups: %d\n",pac->groups);
    LogMessage("\t\thashtest: %d\n",pac->hashtest);
}

static void Preproc_FreeContext ( AnomalydetectionConfig* pc)
{
    if ( pc )
        free(pc);
}

static int Preproc_FreePolicy( tSfPolicyUserContextId set, tSfPolicyId pid, void* pv )
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

    Preproc_FreeSet(ad_context);

    fclose(outputIPsdPORTsd_diff);
    fclose(outputIPsdPORTs_diff);
    fclose(outputIPsdPORTd_diff);
    fclose(outputIPsd_diff);
    fclose(outputIPs_diff);
    fclose(outputIPd_diff);

    CGT_Destroy(cgtIPSD_PSD);
    CGT_Destroy(cgtIPSD_PSD_old);
    CGT_Destroy(cgtIPSD_PS);
    CGT_Destroy(cgtIPSD_PS_old);
    CGT_Destroy(cgtIPSD_PD);
    CGT_Destroy(cgtIPSD_PD_old);
    CGT_Destroy(cgtIPSD);
    CGT_Destroy(cgt_oldIPSD);
    CGT_Destroy(cgtIPS);
    CGT_Destroy(cgt_oldIPS);
    CGT_Destroy(cgtIPD);
    CGT_Destroy(cgt_oldIPD);

    VGT_Destroy(vgtIPSD_PSD);
    VGT_Destroy(vgtIPSD_PSD_old);
    VGT_Destroy(vgtIPSD_PS);
    VGT_Destroy(vgtIPSD_PS_old);
    VGT_Destroy(vgtIPSD_PD);
    VGT_Destroy(vgtIPSD_PD_old);
    VGT_Destroy(vgtIPSD);
    VGT_Destroy(vgt_oldIPSD);
    VGT_Destroy(vgtIPS);
    VGT_Destroy(vgt_oldIPS);
    VGT_Destroy(vgtIPD);
    VGT_Destroy(vgt_oldIPD);


}

static void AD_PrintStats(int exiting)
{   
    // tSfPolicyId pid = getNapRuntimePolicy();
    // AnomalydetectionConfig* pac = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);

}


/*******************************************/
/********  Without implementation **********/
/*******************************************/

static void AD_Reset (int signal, void *foo) { }
static void AD_PostConfigInit (struct _SnortConfig *sc, void *data){ }
static int Preproc_CheckPolicy (struct _SnortConfig *sc, tSfPolicyUserContextId set, tSfPolicyId pid, void* pv) 
{ 
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
static void AD_ResetStats(int signal, void *foo){ }

/********************************************/
/***   Not implementation SNORT_RELOAD    ***/
/********************************************/

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

    return 0;
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



static void loadFile(FILE ** pfile, char *s1, char *s2)
{
    char *path = malloc(strlen(s1)+strlen(s2)+1);//+1 for the zero-terminator
    //in real code you would check for errors in malloc here
    strcpy(path, s1);
    strcat(path, s2);
    
    *pfile = fopen(path,"a");
}


static int compare(const void * a, const void * b)
{
  return (*(float*)a >= *(float*)b) ? 1 : -1;
}

static time_t increaseTime(time_t timec, int delta)
{
    struct tm* tm = localtime(&timec);
    tm->tm_sec += delta;
    return mktime(tm);
}
