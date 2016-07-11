#ifndef __SPP_anomalydetection_H__
#define __SPP_anomalydetection_H__

typedef struct _AnomalydetectionConfig     
{
    char LogPath[100];
    int nlog;
    int alert;
    int GatherTime;
    float phi;  //porcentaje de las diferencias totales en la ventana de tiempo
    float epsilon; //actor de aproximacion 
    float delta; //probabilidad de falla
    int groups;   //numero de grupso totales 
    int hashtest; //numero de test hash que se realizan. 

} AnomalydetectionConfig;

void SetupAnomalyDetection();

#endif  /* __SPP_anomalydetection_H__ */
