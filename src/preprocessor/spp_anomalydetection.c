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
VGT_type *vgt, *vgt_old;
CGT_type *cgt124, *cgt124_old;
VGT_type *vgt124, *vgt124_old;
CGT_type *cgt123, *cgt123_old;
VGT_type *vgt123, *vgt123_old;
CGT_type *cgtIPSRC, *cgt_oldIPSRC;
VGT_type *vgtIPSRC, *vgt_oldIPSRC;
CGT_type *cgtIPDST, *cgt_oldIPDST;
VGT_type *vgtIPDST, *vgt_oldIPDST;


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
static void PrintConf_AD (const AnomalydetectionConfig*);
void preprocFreeOutputList(unsigned int **);

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
    cgt_old = CGT_Init(ad_Config->groups,ad_Config->hashtest,ad_Config->lgn);
    vgt = VGT_Init(ad_Config->groups,ad_Config->hashtest);
    vgt_old = VGT_Init(ad_Config->groups,ad_Config->hashtest);

    cgt123 = CGT_Init(ad_Config->groups,ad_Config->hashtest,ad_Config->lgn);
    cgt123_old = CGT_Init(ad_Config->groups,ad_Config->hashtest,ad_Config->lgn);
    vgt123 = VGT_Init(ad_Config->groups,ad_Config->hashtest);
    vgt123_old = VGT_Init(ad_Config->groups,ad_Config->hashtest);

    cgt124 = CGT_Init(ad_Config->groups,ad_Config->hashtest,ad_Config->lgn);
    cgt124_old = CGT_Init(ad_Config->groups,ad_Config->hashtest,ad_Config->lgn);
    vgt124 = VGT_Init(ad_Config->groups,ad_Config->hashtest);
    vgt124_old = VGT_Init(ad_Config->groups,ad_Config->hashtest);

    cgtIPSRC = CGT_Init(ad_Config->groups,ad_Config->hashtest,32);
    cgt_oldIPSRC = CGT_Init(ad_Config->groups,ad_Config->hashtest,32);
    vgtIPSRC = VGT_Init(ad_Config->groups,ad_Config->hashtest);
    vgt_oldIPSRC = VGT_Init(ad_Config->groups,ad_Config->hashtest);

    cgtIPDST = CGT_Init(ad_Config->groups,ad_Config->hashtest,32);
    cgt_oldIPDST = CGT_Init(ad_Config->groups,ad_Config->hashtest,32);
    vgtIPDST = VGT_Init(ad_Config->groups,ad_Config->hashtest);
    vgt_oldIPDST = VGT_Init(ad_Config->groups,ad_Config->hashtest);

    /* Agrega el preprocesar a una lista con prioridades al momento de acceder al dato bruto */
    AddFuncToPreprocList( sc, PreprocFunction, PRIORITY_SCANNER,  PP_SFPORTSCAN, PROTO_BIT__ALL);
    /* Agrega a la session_api para que el preprocesador reciba los paquetes desde la entrada */
    session_api->enable_preproc_all_ports( sc, PP_SFPORTSCAN, PROTO_BIT__ALL );

    countpaket = 0;
    dataflow = fopen("/var/log/snort/dataflow.txt","a");
    if ( dataflow != NULL && ftell(dataflow) == 0 )
        {
            LogMessage("AnomalyDetection: Creating new DATAFLOW file\n");
            fprintf(dataflow,"DATE,IP_SRC,IP_SRC_d,IP_DST,IP_DST_d,PORT_SRC,PORT_DST,DSIZE,PKLEN,IP_LEN,IP_PROTO,TH_FLAG\n");   
        }else{
            LogMessage("AnomalyDetection: Opened an existing DATAFLOW\n");
        }


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
            CGT_Update96(cgt, ipsrc,ipdst, srcport, dstport, packetsize,(int)p->dsize);
            CGT_Update96(cgt_old, ipsrc,ipdst, srcport, dstport, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update96(vgt, ipsrc,ipdst, srcport, dstport, packetsize); 
            VGT_Update96(vgt_old, ipsrc,ipdst, srcport, dstport, -1*packetsize); 

            CGT_Update96(cgt123, ipsrc,ipdst, srcport, 0, packetsize,(int)p->dsize);
            CGT_Update96(cgt123_old, ipsrc,ipdst, srcport, 0, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update96(vgt123, ipsrc,ipdst, srcport, 0, packetsize); 
            VGT_Update96(vgt123_old, ipsrc,ipdst, srcport, 0, -1*packetsize);   

            CGT_Update96(cgt124, ipsrc,ipdst, 0, dstport, packetsize,(int)p->dsize);
            CGT_Update96(cgt124_old, ipsrc,ipdst, 0, dstport, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update96(vgt124, ipsrc,ipdst, 0, dstport, packetsize); 
            VGT_Update96(vgt124_old, ipsrc,ipdst, 0, dstport, -1*packetsize);   

            CGT_Update(cgtIPSRC, ipsrc, packetsize,(int)p->dsize);
            CGT_Update(cgt_oldIPSRC, ipsrc, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update(vgtIPSRC, ipsrc, packetsize); 
            VGT_Update(vgt_oldIPSRC, ipsrc, -1*packetsize);                    

            CGT_Update(cgtIPDST, ipdst, packetsize,(int)p->dsize);
            CGT_Update(cgt_oldIPDST, ipdst, -1*packetsize,-1*(int)p->dsize); 
            VGT_Update(vgtIPDST, ipdst, packetsize); 
            VGT_Update(vgt_oldIPDST, ipdst, -1*packetsize);  
        }
    }
       
        if(p->iph!= NULL){
            inet_ntop(AF_INET,&p->iph->ip_src,iphs,INET_ADDRSTRLEN);
            inet_ntop(AF_INET,&p->iph->ip_dst,iphd,INET_ADDRSTRLEN);
            time( &timestampDF );

            tmlocal = localtime(&timestampDF);
            strftime(strdate, 200, "\"%x %X\"", tmlocal);
            if(p->tcph != NULL){
                fprintf(dataflow,"%s,\"%s\",%u,\"%s\",%u,%06u,%06u,%u,%u,%u,%03u,%04u\n",strdate, iphs, p->iph->ip_src, iphd, p->iph->ip_dst, p->sp, p->dp, p->dsize, p->pkth->pktlen, p->iph->ip_len, p->iph->ip_proto, p->tcph->th_flags);
            }
            else{
                fprintf(dataflow,"%s,\"%s\",%u,\"%s\",%u,%06u,%06u,%u,%u,%u,%03u,-0001\n",strdate, iphs, p->iph->ip_src, iphd, p->iph->ip_dst, p->sp, p->dp, p->dsize, p->pkth->pktlen, p->iph->ip_len, p->iph->ip_proto);            }
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
static long long ComputeThresh(CGT_type *cgt)
{
    tSfPolicyId pid = sfPolicyUserPolicyGet(ad_context);//getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);

    int ihash, jgroup;
    long long count[pc->hashtest], thresh;

    for(ihash = 0; ihash < pc->hashtest; ihash++)
    {
        count[ihash] = 0;
        for(jgroup = 0; jgroup < pc->groups; jgroup++)
        {
            count[ihash] += abs(cgt->counts[ihash*pc->hashtest+jgroup][0]);
        }
    }

    qsort(count, pc->hashtest, sizeof(long long), compare);
    thresh =  (long long)(pc->phi*count[(int)pc->hashtest/2]);
    LogMessage("#packet CGT.count: %lld | Thresh: %lld \n",cgt->count, thresh);
    return thresh;
}

static long long ComputeDiffThresh(CGT_type *cgt)
{
    tSfPolicyId pid = sfPolicyUserPolicyGet(ad_context);//getNapRuntimePolicy();
    AnomalydetectionConfig* pc = (AnomalydetectionConfig*)sfPolicyUserDataGet(ad_context, pid);

    int ihash, jgroup;
    long long count[pc->hashtest], thresh;
    for(ihash = 0; ihash < pc->hashtest; ihash++)
    {
        count[ihash] = 0;
        for(jgroup = 0; jgroup < pc->groups; jgroup++)
        {   
            count[ihash] += abs(cgt->counts[ihash*pc->hashtest+jgroup][0]);
        }
    }
    qsort(count, pc->hashtest, sizeof(long long), compare);
    thresh =  (long long)(pc->phi*count[(int)pc->hashtest/2]);
    LogMessage("#packet CGT.count: %lld | Thresh DIFF: %lld \n",count[(int)pc->hashtest/2], thresh);
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
    unsigned int ** outputList, ** outputList123, ** outputList124, **outputListIPSRC;
    unsigned int ** outputDiffList, ** outputDiffList123, ** outputDiffList124, **outputDiffListIPSRC;
    double TimeInterval;
    int i,nlist,ndifflist;
    struct tm* tmlocal;
    char strdate[200];

    

    if(flag==0) //check if it is new file, all new log files need to have header
    {
        file2=fopen(pc->LogPath,"a");
        if ( file2 != NULL && ftell(file2) == 0 )
        {
            LogMessage("AnomalyDetection: Creating new log file in %s.\n",pc->LogPath);
            time( &LastLogTime );
            fprintf(file2,"Date,Ipsrc,Ipdst,Ps,Pd,#Packets,AVGSize\n");
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
            file2=fopen(pc->LogPath,"a");

            //SaveToLog(LastLogTime); //save in the log file the current count data
            LogMessage("\n************************************************************************\n");
            LogMessage("AnomalyDetection log time:  %s\n",ctime(&LastLogTime));
            LogMessage("Paquetes capturados por SNORT: %d\n",countpaket);
            LogMessage("=================  IPsrc IPdst Psrc Pdst Packets Dsize  =================  \n");
            outputList = CGT_Output96(cgt, vgt, ComputeThresh(cgt));            
            if ( file2 != NULL)
            {
                if(outputList != NULL){
                    LogMessage("Numero de salidas: %d\n",outputList[0][0]-1);
                    for(i=1; i < outputList[0][0]; i++)
                    {
                        LogMessage("CANDIDATO ==> ipsrc %3u.%3u.%3u.%3u" ,(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24);
                        LogMessage(" ipdst %3u.%3u.%3u.%3u" ,(outputList[i][1] & 0x000000ff),(outputList[i][1] & 0x0000ff00) >> 8,(outputList[i][1] & 0x00ff0000) >> 16,(outputList[i][1] & 0xff000000) >> 24);
                        LogMessage(" portSrc %5u portDst %5u packet %u size %u\n", (outputList[i][2]>>16), ((outputList[i][2]<<16)>>16),outputList[i][3], outputList[i][4]);
                        tmlocal = localtime(&LastLogTime);
                        strftime(strdate, 200, "\"%x %X\"", tmlocal);
                        fprintf(file2,"%s,", strdate);
                        fprintf(file2,"\"%u.%u.%u.%u\",",(outputList[i][0] & 0x000000ff),(outputList[i][0] & 0x0000ff00) >> 8,(outputList[i][0] & 0x00ff0000) >> 16,(outputList[i][0] & 0xff000000) >> 24);
                        fprintf(file2,"\"%u.%u.%u.%u\",",(outputList[i][1] & 0x000000ff),(outputList[i][1] & 0x0000ff00) >> 8,(outputList[i][1] & 0x00ff0000) >> 16,(outputList[i][1] & 0xff000000) >> 24);
                        fprintf(file2,"%u,%u,%u,%u\n",(outputList[i][2]>>16), ((outputList[i][2]<<16)>>16),outputList[i][3], outputList[i][4]);
                    }
                }
            }
            fclose(file2);


            outputDiffList = CGT_Output96(cgt_old, vgt_old, ComputeDiffThresh(cgt_old));
            // if(outputDiffList != NULL){
            //     LogMessage("Numero de salidas DIFF: %d\n",outputDiffList[0][0]-1);
            //     for(i=1; i < outputDiffList[0][0]; i++)
            //     {
            //         LogMessage("CANDIDATO DIFF==> ipsrc %3u.%3u.%3u.%3u" ,(outputDiffList[i][0] & 0x000000ff),(outputDiffList[i][0] & 0x0000ff00) >> 8,(outputDiffList[i][0] & 0x00ff0000) >> 16,(outputDiffList[i][0] & 0xff000000) >> 24);
            //         LogMessage(" ipdst %3u.%3u.%3u.%3u" ,(outputDiffList[i][1] & 0x000000ff),(outputDiffList[i][1] & 0x0000ff00) >> 8,(outputDiffList[i][1] & 0x00ff0000) >> 16,(outputDiffList[i][1] & 0xff000000) >> 24);
            //         LogMessage(" portSrc %5u portDst %5u packet %d size %d\n", (outputDiffList[i][2]>>16), ((outputDiffList[i][2]<<16)>>16),outputDiffList[i][3],outputDiffList[i][4]);
            //     }
            // } 

            CGT_Destroy(cgt_old);
            VGT_Destroy(vgt_old);
            cgt_old = cgt;
            vgt_old = vgt;
            cgt = CGT_Init(pc->groups,pc->hashtest,pc->lgn);
            vgt = VGT_Init(pc->groups,pc->hashtest);
            if(outputList != NULL){
            //     nlist = outputList[0][0];
            //     for(i = 0; i < nlist; i++){
            //         free(outputList[i]);
            //     }
            //     free(outputList);                
                preprocFreeOutputList(outputList);

            }

            if(outputDiffList != NULL){
            //     ndifflist = outputDiffList[0][0];
            //     for(i = 0; i < ndifflist; i++){
            //         free(outputDiffList[i]);
            //     free(outputDiffList);
                preprocFreeOutputList(outputDiffList);

            }

            LogMessage("=================   IPsrc IPdst Psrc  - Packets Dsize  =================  \n");
            outputList123 = CGT_Output96(cgt123, vgt123, ComputeThresh(cgt123));
            outputDiffList123 = CGT_Output96(cgt123_old, vgt123_old, ComputeDiffThresh(cgt123_old));    

            CGT_Destroy(cgt123_old);
            VGT_Destroy(vgt123_old);
            cgt123_old = cgt123;
            vgt123_old = vgt123;
            cgt123 = CGT_Init(pc->groups,pc->hashtest,pc->lgn);
            vgt123 = VGT_Init(pc->groups,pc->hashtest);
            if(outputList123 != NULL) {
                preprocFreeOutputList(outputList123);
            }
            if(outputDiffList123 != NULL) 
                preprocFreeOutputList(outputDiffList123);

            LogMessage("=================  IPsrc IPdst - Pdst Packets Dsize  =================  \n");
            outputList124 = CGT_Output96(cgt124, vgt124, ComputeThresh(cgt124));
            outputDiffList124 = CGT_Output96(cgt124_old, vgt124_old, ComputeDiffThresh(cgt124_old));    

            CGT_Destroy(cgt124_old);
            VGT_Destroy(vgt124_old);
            cgt124_old = cgt124;
            vgt124_old = vgt124;
            cgt124 = CGT_Init(pc->groups,pc->hashtest,pc->lgn);
            vgt124 = VGT_Init(pc->groups,pc->hashtest);
            if(outputList124 != NULL) 
                preprocFreeOutputList(outputList124);
            if(outputDiffList124 != NULL) 
                preprocFreeOutputList(outputDiffList124);     
            
            LogMessage("=================  IPsrc Packets Dsize  =================  \n");
            outputListIPSRC = CGT_Output(cgtIPSRC, vgtIPSRC, ComputeThresh(cgtIPSRC));
            outputDiffListIPSRC = CGT_Output(cgt_oldIPSRC, vgt_oldIPSRC, ComputeDiffThresh(cgt_oldIPSRC));    

            CGT_Destroy(cgt_oldIPSRC);
            VGT_Destroy(vgt_oldIPSRC);
            cgt_oldIPSRC = cgtIPSRC;
            vgt_oldIPSRC = vgtIPSRC;
            cgtIPSRC = CGT_Init(pc->groups,pc->hashtest,32);
            vgtIPSRC = VGT_Init(pc->groups,pc->hashtest);
            if(outputListIPSRC != NULL) 
                preprocFreeOutputList(outputListIPSRC);
            if(outputDiffListIPSRC != NULL) 
                preprocFreeOutputList(outputDiffListIPSRC);        
            
            LogMessage("=================  IPdst Packets Dsize  =================  \n");
            outputListIPSRC = CGT_Output(cgtIPDST, vgtIPDST, ComputeThresh(cgtIPDST));
            outputDiffListIPSRC = CGT_Output(cgt_oldIPDST, vgt_oldIPDST, ComputeDiffThresh(cgt_oldIPDST));    

            CGT_Destroy(cgt_oldIPDST);
            VGT_Destroy(vgt_oldIPDST);
            cgt_oldIPDST = cgtIPDST;
            vgt_oldIPDST = vgtIPDST;
            cgtIPDST = CGT_Init(pc->groups,pc->hashtest,32);
            vgtIPDST = VGT_Init(pc->groups,pc->hashtest);
            if(outputListIPSRC != NULL) 
                preprocFreeOutputList(outputListIPSRC);
            if(outputDiffListIPSRC != NULL) 
                preprocFreeOutputList(outputDiffListIPSRC);  
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


void preprocFreeOutputList(unsigned int ** outputList){
    int i,nlist;
    
    nlist = **outputList;
    // LogMessage("Nlist %d\n",nlist);
    for(i = 0; i < nlist; i++)
        free(*(outputList+i));
    free(outputList); 
    // LogMessage("Liberado...\n");
}
/* Function: SaveToLog(time_t LastLogTime)
 *
 * Purpose: Save current state of containers to log file.
 *
 * Arguments: LastLogTime => contains the last logging time.
 *
 * Returns: void function
 */

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






