//DOM-IGNORE-BEGIN
/*******************************************************************************
Copyright (C) 2021 released Microchip Technology Inc.  All rights reserved.

Microchip licenses to you the right to use, modify, copy and distribute
Software only when embedded on a Microchip microcontroller or digital signal
controller that is integrated into your product or third party product
(pursuant to the sublicense terms in the accompanying license agreement).

You should refer to the license agreement accompanying this Software for
additional information regarding your rights and obligations.

SOFTWARE AND DOCUMENTATION ARE PROVIDED AS IS WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION, ANY WARRANTY OF
MERCHANTABILITY, TITLE, NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.
IN NO EVENT SHALL MICROCHIP OR ITS LICENSORS BE LIABLE OR OBLIGATED UNDER
CONTRACT, NEGLIGENCE, STRICT LIABILITY, CONTRIBUTION, BREACH OF WARRANTY, OR
OTHER LEGAL EQUITABLE THEORY ANY DIRECT OR INDIRECT DAMAGES OR EXPENSES
INCLUDING BUT NOT LIMITED TO ANY INCIDENTAL, SPECIAL, INDIRECT, PUNITIVE OR
CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA, COST OF PROCUREMENT OF
SUBSTITUTE GOODS, TECHNOLOGY, SERVICES, OR ANY CLAIMS BY THIRD PARTIES
(INCLUDING BUT NOT LIMITED TO ANY DEFENSE THEREOF), OR OTHER SIMILAR COSTS.
 *******************************************************************************/
//DOM-IGNORE-END
/*******************************************************************************
  MPLAB Harmony Application Source File

  Company:
    Microchip Technology Inc.

  File Name:
    sys_ota.c

  Summary:
    Source code for the OTA system service implementation.

  Description:
    This file contains the source code for the OTA system service
    implementation.
 *******************************************************************************/

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************


#include "system_definitions.h"
#include "system/ota/framework/cjson/cjson.h"
#include "system/../wolfssl/wolfcrypt/types.h"
#include "system/../wolfssl/wolfcrypt/ecc.h"
#include "system/../wolfssl/wolfcrypt/tfm.h"
#include "system/../wolfssl/wolfcrypt/asn_public.h"
#include <wolfssl/wolfcrypt/coding.h>

// *****************************************************************************
// *****************************************************************************
// Section: Global Data Definitions
// *****************************************************************************
// *****************************************************************************

#define SYS_CONSOLE_DEBUG1          SYS_CONSOLE_PRINT

/*Macro to define maximum downloader read operation to perform, if client is continuously unable to receive 
 * data from server */
#define MAX_DOWNLOADER_READ_COUNT   70000

#define SYS_OTA_GET_STATUS_STR(status)  \
    (status == SYS_OTA_IDLE)?"IDLE" : \
    (status == SYS_OTA_WAITING_FOR_NETWORK_CONNECTION)?"WAITING_FOR_NETWRK_CONNECTION" : \
    (status == SYS_OTA_WAITING_FOR_OTACORE_IDLE)?"WAITING_FOR_OTACORE_IDLE" : \
    (status == SYS_OTA_WAITING_FOR_USER_DEFINED_PERIOD)?"WAITING_FOR_USER_DEFINED_PERIOD" : \
    (status == SYS_OTA_UPDATE_CHECK_START)?"UPDATE_CHECK_START" : \
    (status == SYS_OTA_UPDATE_CHECK_FAILED)?"UPDATE_CHECK_FAILED" : \
    (status == SYS_OTA_UPDATE_AVAILABLE)?"UPDATE_AVAILABLE" : \
    (status == SYS_OTA_UPDATE_NOTAVAILABLE)?"UPDATE_NOTAVAILABLE" : \
    (status == SYS_OTA_TRIGGER_OTA_FAILED)?"TRIGGER_OTA_FAILED" : \
    (status == SYS_OTA_FACTORY_RESET_SUCCESS)?"FACTORY_RESET_SUCCESS" : \
    (status == SYS_OTA_FACTORY_RESET_FAILED)?"FACTORY_RESET_FAILED" : \
    (status == SYS_OTA_ROLLBACK_SUCCESS)?"ROLLBACK_SUCCESS" : \
    (status == SYS_OTA_ROLLBACK_FAILED)?"ROLLBACK_FAILED" : \
    (status == SYS_OTA_DOWNLOAD_START)?"DOWNLOAD_IN_PROGRESS" : \
    (status == SYS_OTA_DOWNLOAD_SUCCESS)?"DOWNLOAD_SUCCESS" : \
    (status == SYS_OTA_DOWNLOAD_FAILED)?"DOWNLOAD_FAILED" : \
    (status == SYS_OTA_IMAGE_DIGEST_VERIFY_START)?"IMAGE_DIGEST_VERIFY_START" : "Invalid Status"

/*pointer to register user callback function*/
static SYS_OTA_CALLBACK g_otaSrvcCallBack;

/*variable for ota parameters*/
static OTA_PARAMS ota_params;

/*variable for downloader*/
static DRV_HANDLE downloader;

/*variable to check TLS request*/
static bool sys_ota_tls;

extern size_t field_content_length;
#ifdef SYS_OTA_CLICMD_ENABLED
/*************************************************************/
static uint32_t g_u32SysOtaInitDone = 0;
/*************************************************************/
#endif

/*Data structure which has the MHC configuration for the OTA service*/
SYS_OTA_Config g_SysOtaConfig; 

/*variable for ota service parameters*/
SYS_OTA_DATA sys_otaData;


#define TERM_GREEN "\x1B[32m"
#define TERM_RED   "\x1B[31m"
#define TERM_YELLOW "\x1B[33m"
#define TERM_RESET "\x1B[0m"

SYS_OTA_FILE_DATA g_SysFileData = {0,0};
static bool g_key_present = false;
static uint8_t g_public_key_slot = 0;
static bool g_secure_download = false;
static uint8_t g_formulated_digest[32];


static SYS_OTA_FILE_DOWNLOAD_STATUS File_Dnld_Status = SYS_OTA_PARSE_JSON;
    

static bool SYS_OTA_FILE_Params_Initialize
(
    void
);
static bool SYS_OTA_Parse_JSON
(
    uint8_t index
);
static bool SYS_OTA_Get_Key_Data
(
    cJSON *cert_data
);
static void SYS_OTA_File_Download_Tasks
(
    void
);
static bool SYS_OTA_NVM_Read
(
    uint32_t addr, 
    uint8_t* buff, 
    uint32_t len
);
static bool SYS_OTA_NVM_Write
(
    uint32_t addr, 
    uint8_t* buff, 
    uint32_t len
);
static bool SYS_OTA_CheckSlot
(
    int slot_number
);

static bool SYS_OTA_Download_File
(
    char *file_URL
);

static bool SYS_OTA_Get_File_Data
(
    cJSON *file_data
);
 
void SYS_OTA_Print_Server_Data
(
    void
);
 


// *****************************************************************************
// *****************************************************************************
// Section: Local Functions
// *****************************************************************************
// *****************************************************************************


// *****************************************************************************
// *****************************************************************************
// Section: To get autoreset configuration
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_GetAutoReset(void) {
    return g_SysOtaConfig.autoreset;
}

// *****************************************************************************
// *****************************************************************************
// Section: To check if OTA timer triggered
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_IsOtaTimerTriggered(void) {
    return sys_otaData.ota_timer_trigger;
}
// *****************************************************************************
// *****************************************************************************
// Section: To check if auto update check enabled by user
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_IsAutoUpdtChckEnbl(void) {
    return g_SysOtaConfig.ota_periodic_check;
}

// *****************************************************************************
// *****************************************************************************
// Section: To check if auto Download  enabled by user
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_IsAutoUpdtEnbl(void) {
    return g_SysOtaConfig.ota_auto_update;
}

// *****************************************************************************
// *****************************************************************************
// Section: To check system is connected to network or not
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_ConnectedToNtwrk(void) {
    return sys_otaData.dev_cnctd_to_nw;
}

// *****************************************************************************
// *****************************************************************************
// Section: To check if OTA process already in progress
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_IsOtaInProgress(void) {
    return sys_otaData.otaFwInProgress;
}

// *****************************************************************************
// *****************************************************************************
// Section: To check if update check with server in progress
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_IsUpdateCheckInProgress(void) {
    return sys_otaData.otaUpdateCheckInProgress;
}

// *****************************************************************************
// *****************************************************************************
// Section: To check if erase is in progress
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_IsEraseInProgress(void) {
    return sys_otaData.otaEraseInProgress;
}

// *****************************************************************************
// *****************************************************************************
// Section: To check if image download success
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_IsDownloadSuccess(void) {
    return sys_otaData.download_success;
}

// *****************************************************************************
// *****************************************************************************
// Section: To check if image download success
// *****************************************************************************
// *****************************************************************************

static inline bool SYS_OTA_IsEraseImageRequest(void) {
    return sys_otaData.erase_request;
}

// *****************************************************************************
// *****************************************************************************
// Section:  OTA service result 
// *****************************************************************************
// *****************************************************************************

static inline void SYS_OTA_SetOtaServicStatus(SYS_OTA_STATUS status) {
    sys_otaData.ota_srvc_status = status;
}

static bool SYS_OTA_Update_Check();
// *****************************************************************************
// *****************************************************************************
// Section: Call back function to OTA core
// *****************************************************************************
// *****************************************************************************

void _OTACallback(uint32_t event, void * data, void *cookies) {

    switch (event) {
        
#ifdef SYS_OTA_PATCH_ENABLE
        case OTA_RESULT_PATCH_BASEVERSION_NOTFOUND:
        {
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("SYS OTA : OTA_RESULT_PATCH_BASEVERSION_NOTFOUND\r\n");
#endif
            SYS_OTA_SetOtaServicStatus(SYS_OTA_PATCH_BASEVERSION_NOTFOUND);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        case OTA_RESULT_PATCH_EVENT_START:
        {
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("SYS OTA : OTA_RESULT_PATCH_EVENT_START\r\n");
#endif
            SYS_OTA_SetOtaServicStatus(SYS_OTA_PATCH_EVENT_START);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        
        case OTA_RESULT_PATCH_EVENT_COMPLETED:
        {
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("SYS OTA : OTA_RESULT_PATCH_EVENT_COMPLETED\r\n");
#endif
            SYS_OTA_SetOtaServicStatus(SYS_OTA_PATCH_EVENT_COMPLETED);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
#endif
        
        case OTA_RESULT_IMAGE_DOWNLOAD_START:
        {
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("SYS OTA : OTA_RESULT_IMAGE_DOWNLOAD_START\r\n");
#endif
            SYS_OTA_SetOtaServicStatus(SYS_OTA_DOWNLOAD_START);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        case OTA_RESULT_IMAGE_DOWNLOADED:
        {
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("SYS OTA : Completed OTA Successfully\r\n");
#endif
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            SYS_OTA_SetOtaServicStatus(SYS_OTA_DOWNLOAD_SUCCESS);
            break;
        }
        case OTA_RESULT_IMAGE_DOWNLOAD_FAILED:
        {
            sys_otaData.otaFwInProgress = false;
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            SYS_OTA_SetOtaServicStatus(SYS_OTA_DOWNLOAD_FAILED);
            break;
        }
        case OTA_RESULT_IMAGE_DIGEST_VERIFY_START:
        {
            SYS_OTA_SetOtaServicStatus(SYS_OTA_IMAGE_DIGEST_VERIFY_START);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        case OTA_RESULT_IMAGE_DIGEST_VERIFY_SUCCESS:
        {
            SYS_OTA_SetOtaServicStatus(SYS_OTA_IMAGE_DIGEST_VERIFY_SUCCESS);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        case OTA_RESULT_IMAGE_DIGEST_VERIFY_FAILED:
        {
            sys_otaData.otaFwInProgress = false;
            SYS_OTA_SetOtaServicStatus(SYS_OTA_IMAGE_DIGEST_VERIFY_FAILED);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("SYS OTA : SYS OTA Image verification failed\r\n");
#endif
            break;
        }
        
#ifdef SYS_OTA_PATCH_ENABLE
        case OTA_RESULT_PATCH_IMAGE_DIGEST_VERIFY_START:
        {
            SYS_OTA_SetOtaServicStatus(SYS_OTA_PATCH_IMAGE_DIGEST_VERIFY_START);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        case OTA_RESULT_PATCH_IMAGE_DIGEST_VERIFY_SUCCESS:
        {
            SYS_OTA_SetOtaServicStatus(SYS_OTA_PATCH_IMAGE_DIGEST_VERIFY_SUCCESS);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("SYS OTA : SYS OTA Patch Image verification success\r\n");
#endif
            break;
        }
        case OTA_RESULT_PATCH_IMAGE_DIGEST_VERIFY_FAILED:
        {
            sys_otaData.otaFwInProgress = false;
            SYS_OTA_SetOtaServicStatus(SYS_OTA_PATCH_IMAGE_DIGEST_VERIFY_FAILED);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("SYS OTA : SYS OTA Image verification failed\r\n");
#endif
            break;
        }
#endif
        case OTA_RESULT_IMAGE_STATUS_SET:
        {
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("OTA_RESULT_IMAGE_STATUS_SET\r\n");
#endif
            
            if (SYS_OTA_IsOtaInProgress() == true) {
                SYS_OTA_SetOtaServicStatus(SYS_OTA_DB_ENTRY_SUCCESS);
                sys_otaData.state = SYS_OTA_UPDATE_USER;
                sys_otaData.download_success = true;
                sys_otaData.otaFwInProgress = false;
            }
            break;
        }
        case OTA_RESULT_IMAGE_ERASE_FAILED:
        {
            sys_otaData.otaEraseInProgress = false;
            SYS_OTA_SetOtaServicStatus(SYS_OTA_IMAGE_ERASE_FAILED);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        case OTA_RESULT_IMAGE_ERASED:
        {
            sys_otaData.otaEraseInProgress = false;
            SYS_OTA_SetOtaServicStatus(SYS_OTA_IMAGE_ERASED);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        case OTA_RESULT_IMAGE_DATABASE_FULL:
        {
            SYS_OTA_SetOtaServicStatus(SYS_OTA_IMAGE_DATABASE_FULL);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        case OTA_RESULT_FACTORY_RESET_SUCCESS:
        {
            SYS_OTA_SetOtaServicStatus(SYS_OTA_FACTORY_RESET_SUCCESS);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
        case OTA_RESULT_ROLLBACK_DONE:
        {
            SYS_OTA_SetOtaServicStatus(SYS_OTA_ROLLBACK_SUCCESS);
            sys_otaData.state = SYS_OTA_UPDATE_USER;
            break;
        }
    }
}


// *****************************************************************************
// *****************************************************************************
// Section: Wifi service callback function
// *****************************************************************************
// *****************************************************************************

//void WiFiServCallback(uint32_t event, void * data, void *cookie) {
//
//    switch (event) {
//        case SYS_WIFI_CONNECT:
//        {
//            SYS_CONSOLE_PRINT("Device CONNECTED \r\n");
//            sys_otaData.dev_cnctd_to_nw = true;
//            break;
//        }
//        case SYS_WIFI_DISCONNECT:
//        {
//            SYS_CONSOLE_PRINT("Device DISCONNECTED \r\n");
//            break;
//        }
//        case SYS_WIFI_PROVCONFIG:
//        {
//            SYS_CONSOLE_PRINT("Received the Provisioning data \r\n");
//            break;
//        }
//    }
//}

// *****************************************************************************
// *****************************************************************************
// Section: To check TLS request
// *****************************************************************************
// *****************************************************************************
static bool SYS_OTA_IsTls_Request(const char *URIText){
    sys_ota_tls = false;
    if (SYS_OTA_ENFORCE_TLS == false) {
        if (0 == strncmp(URIText, "https:", 6)) {
            sys_ota_tls = true;
            return true;
        } else if (0 == strncmp(URIText, "http:", 5)) {
            sys_ota_tls = false;
            return false;
        } else {
            sys_ota_tls = false;
            return false;
        }
    } else {
        if (0 == strncmp(URIText, "https:", 6)) {
            sys_ota_tls = true;
            return true;
        } else {
            sys_ota_tls = false;
            return false;
        }
    }
}

// *****************************************************************************
// *****************************************************************************
// Section: parsing JSON file content
// *****************************************************************************
// *****************************************************************************

static bool SYS_OTA_ParseJsonContent(cJSON *config_json) {
    bool err = false;
    cJSON *server_array = OTA_cJSON_GetObjectItem(config_json, "ota");
    int server_array_count = OTA_cJSON_GetArraySize(server_array);
    char *ota_url;
    cJSON *server_data = OTA_cJSON_GetArrayItem(server_array, server_array_count - 1);
    cJSON *serv_digest = OTA_cJSON_GetObjectItem(server_data, "Digest");	
    #ifdef SYS_OTA_SECURE_BOOT_ENABLED
    cJSON *serv_digest_sign = OTA_cJSON_GetObjectItem(server_data, "Signature");
    #endif
    cJSON *ota_url_l = OTA_cJSON_GetObjectItem(server_data, "URL");
    cJSON *ota_image_version = OTA_cJSON_GetObjectItem(server_data, "Version");
    cJSON *erasever = OTA_cJSON_GetObjectItem(server_data, "EraseVer");
    
#ifdef SYS_OTA_PATCH_ENABLE    
    cJSON *patch_array = OTA_cJSON_GetObjectItem(server_data, "Patch");
#endif    

    /*go through json array for mandatory fields*/
    if (erasever != NULL) {
        if (OTA_cJSON_IsBool(erasever)) {
            if (OTA_cJSON_IsTrue(erasever)) {
                if (ota_image_version != NULL) {
                    /*proceed further*/
                    sys_otaData.erase_request = true;
                } else {
                    SYS_CONSOLE_PRINT("SYS OTA : version field is not present in server\r\n");
                    return false;
                }
            } else {
                sys_otaData.erase_request = false;
            }
        } else {
            SYS_CONSOLE_PRINT("SYS OTA : Erase field should be of type bool  : true or false\r\n");
            return false;
        }
    }

    switch (SYS_OTA_IsEraseImageRequest()) {
        case true:
        {
            cJSON *ota_image_version = OTA_cJSON_GetObjectItem(server_data, "Version");
            if (OTA_cJSON_IsNumber(ota_image_version) && (ota_image_version->valueint != 0)) {
                SYS_CONSOLE_PRINT("    Server app version: %d\r\n", (int) ota_image_version->valuedouble);
            } else {
                SYS_CONSOLE_PRINT("SYS OTA : Error parsing version\r\n");
                err = true;
            }

            if (err == true) {
                return false;
            } else {
                sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_DONE;
                sys_otaData.state = SYS_OTA_ERASE_IMAGE;
                ota_params.delete_img_version = ((int) ota_image_version->valuedouble);
                return false;
            }
            break;
        }
        case false:
        {
            if ((ota_image_version != NULL)&& (ota_url_l != NULL) && (serv_digest != NULL)) {
                /*do nothing here, proceed further */
            } else {
                SYS_CONSOLE_PRINT("SYS OTA : Mandatory JSON fields does not exist\r\n");
                return false;
            }
            
#ifdef SYS_OTA_PATCH_ENABLE
            if(patch_array != NULL)
            {
                int patch_array_count = OTA_cJSON_GetArraySize(patch_array);
                int i;
                for(i=(patch_array_count-1);i>= 0;i-- )
                {
                    cJSON *patch_data = OTA_cJSON_GetArrayItem(patch_array, i);
                    cJSON *base_ver = OTA_cJSON_GetObjectItem(patch_data, "BaseVersion");
                    cJSON *base_ver_digest = OTA_cJSON_GetObjectItem(patch_data, "BaseVerDigest");
                    cJSON *patch_url = OTA_cJSON_GetObjectItem(patch_data, "PatchURL");
                    cJSON *patch_digest = OTA_cJSON_GetObjectItem(patch_data, "PatchDigest");
                    cJSON *target_digest = OTA_cJSON_GetObjectItem(patch_data, "TargetDigest");
                    if (base_ver != NULL) {    
                        if (OTA_cJSON_IsString(base_ver_digest) && (base_ver_digest->valuestring != NULL)) {
                            if(SYS_STATUS_READY == OTA_Search_ImageVersion((uint32_t) base_ver->valuedouble,  base_ver_digest->valuestring))
                            {
                                char *serv_app_patch_digest;
                                char *serv_app_base_digest;
                                char *serv_app_target_digest;
                                if (OTA_cJSON_IsString(patch_digest) && (patch_digest->valuestring != NULL)) {
                                        ota_params.patch_base_version = ((int) base_ver->valuedouble);
                                        
                                        serv_app_base_digest = base_ver_digest->valuestring;
                                        strncpy(ota_params.serv_app_base_digest_string, serv_app_base_digest, 64);
                                        
                                        SYS_CONSOLE_PRINT("    Server app patch Digest \"%s\"\r\n", patch_digest->valuestring);
                                        
                                        serv_app_patch_digest = patch_digest->valuestring;
                                        strncpy(ota_params.serv_app_patch_digest_string, serv_app_patch_digest, 64);
                                        if (OTA_cJSON_IsString(patch_url) && (patch_url->valuestring != NULL)) {
                                            SYS_CONSOLE_PRINT("    Server app URL \"%s\"\r\n", patch_url->valuestring);
                                            ota_url = patch_url->valuestring;

                                            memcpy(ota_params.ota_server_url, ota_url, strlen(ota_url) + 1);
                                            sys_otaData.patch_request = true;
                                        } else {
                                            SYS_CONSOLE_PRINT("SYS OTA : Error parsing Server app URL\r\n");
                                            err = true;
                                        }
                                        
                                        if (OTA_cJSON_IsString(target_digest) && (target_digest->valuestring != NULL)) {
                                            SYS_CONSOLE_PRINT("    Server app target Digest \"%s\"\r\n", target_digest->valuestring);
                                            serv_app_target_digest = target_digest->valuestring;
                                            strncpy(ota_params.serv_app_target_digest_string, serv_app_target_digest, 64);
                                        } else {
                                            SYS_CONSOLE_PRINT("SYS OTA : Error parsing Server app target Digest\r\n");
                                            err = true;
                                        }
                                        
                                    } else {
                                        SYS_CONSOLE_PRINT("SYS OTA : Error parsing Server app patch Digest\r\n");
                                        err = true;
                                    }
                                    break;
                            }
                            else{
                                SYS_CONSOLE_PRINT("SYS OTA : Base Image version not found\n\r");
                            }
                            
                        } else {
                            SYS_CONSOLE_PRINT("SYS OTA : For Patch functionality , mandatory \"BaseVersionDigest\" field is not present in Manifest\r\n");
                            return false;
                        }
                    }
                    else {
                        SYS_CONSOLE_PRINT("SYS OTA : For Patch functionality , mandatory \"BaseVersion\" field is not present in Manifest\r\n");
                        return false;
                    }
                }                
            }

            if(sys_otaData.patch_request == false)
            {
            
                if (OTA_cJSON_IsString(ota_url_l) && (ota_url_l->valuestring != NULL)) {
                    SYS_CONSOLE_PRINT("    Server app URL \"%s\"\r\n", ota_url_l->valuestring);
                    ota_url = ota_url_l->valuestring;

                    memcpy(ota_params.ota_server_url, ota_url, strlen(ota_url) + 1);

                } else {
                    SYS_CONSOLE_PRINT("SYS OTA : Error parsing Server app URL\r\n");
                    err = true;
                }
            }
            else
            {
                ota_params.patch_request = true;
            }
#else
            if (OTA_cJSON_IsString(ota_url_l) && (ota_url_l->valuestring != NULL)) {
                    SYS_CONSOLE_PRINT("    Server app URL \"%s\"\r\n", ota_url_l->valuestring);
                    ota_url = ota_url_l->valuestring;

                    memcpy(ota_params.ota_server_url, ota_url, strlen(ota_url) + 1);

            } else {
                    SYS_CONSOLE_PRINT("SYS OTA : Error parsing Server app URL\r\n");
                    err = true;
            }
#endif

#ifdef SYS_OTA_PATCH_ENABLE            
            if(sys_otaData.patch_request == false){
                char *serv_app_digest;
                if (OTA_cJSON_IsString(serv_digest) && (serv_digest->valuestring != NULL)) {
                    SYS_CONSOLE_PRINT("    Server app Digest \"%s\"\r\n", serv_digest->valuestring);
                    serv_app_digest = serv_digest->valuestring;
                    strncpy(ota_params.serv_app_digest_string, serv_app_digest, 64);
                } else {
                    SYS_CONSOLE_PRINT("SYS OTA : Error parsing Server app Digest\r\n");
                    err = true;
                }
            }else{
                strncpy(ota_params.serv_app_digest_string, ota_params.serv_app_target_digest_string, 64);
            }
#else
            char *serv_app_digest;
            if (OTA_cJSON_IsString(serv_digest) && (serv_digest->valuestring != NULL)) {
                SYS_CONSOLE_PRINT("    Server app Digest \"%s\"\r\n", serv_digest->valuestring);
                serv_app_digest = serv_digest->valuestring;
                strncpy(ota_params.serv_app_digest_string, serv_app_digest, 64);
            } else {
                SYS_CONSOLE_PRINT("SYS OTA : Error parsing Server app Digest\r\n");
                err = true;
            }
#ifdef SYS_OTA_SECURE_BOOT_ENABLED            
            char *serv_app_digest_sign;
            if(serv_digest_sign != NULL)
            {
                if (OTA_cJSON_IsString(serv_digest_sign) && (serv_digest_sign->valuestring != NULL)) {
                    SYS_CONSOLE_PRINT("    Server app Signature \"%s\"\r\n", serv_digest_sign->valuestring);
                    serv_app_digest_sign = serv_digest_sign->valuestring;
                    strncpy(ota_params.serv_app_digest_sign_string, serv_app_digest_sign, 96);
                    ota_params.signature_verification = true;
                } else {
                    SYS_CONSOLE_PRINT("SYS OTA : Error parsing Server app Digest Signature\r\n");
                    err = true;
                }
            }
#endif
#endif

            if (OTA_cJSON_IsNumber(ota_image_version) && (ota_image_version->valueint != 0)) {
                SYS_CONSOLE_PRINT("    Server app version: %d\r\n", (int) ota_image_version->valuedouble);
                SYS_CONSOLE_PRINT("    current app version: %d\r\n", g_SysOtaConfig.app_version);
            } else {
                SYS_CONSOLE_PRINT("SYS OTA : Error parsing  version\r\n");
                err = true;
            }
            
            if (err == true) {
                sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_READ_JSON;
                return false;
            } else {
                if (g_SysOtaConfig.app_version < ((int) ota_image_version->valuedouble)) {
                    ota_params.version = ((int) ota_image_version->valuedouble);
                    return true;
                } else {

                        SYS_CONSOLE_PRINT(TERM_YELLOW"SYS_OTA_FILE : JSON parsing  \r\n"TERM_RESET);
                        
                        /* To find the Files array in Json file, if present parse the file and save in array */
                        cJSON *temp_array = NULL, *files_array = NULL;
                        for(int count=0; count < server_array_count; count++)
                        {
                            temp_array = OTA_cJSON_GetArrayItem(server_array,count);
                            files_array = OTA_cJSON_GetObjectItem(temp_array, "files");
                            if(files_array != NULL ) 
                            {
                                g_SysFileData.total_no_of_files = OTA_cJSON_GetArraySize(files_array);
                                sys_otaData.update_check_state = SYS_OTA_DOWNLOAD_FILES;
                                SYS_CONSOLE_PRINT("SYS_OTA_FILE : Files/Imgs present in server - Download img/files Initiated\r\n");
                                break;
                            }
                        }  
                    return false;
                }
            }

            break;
        }
    }
    
}

// *****************************************************************************
// *****************************************************************************
// Section:  SYS OTA Control Message Interface
// *****************************************************************************
// *****************************************************************************
#ifdef SYS_OTA_SECURE_BOOT_ENABLED
void SYS_OTA_StoreFactoryImageSignature(void *buffer){
    
    OTA_StoreFactoryImageSignature(buffer);
}
#endif
// *****************************************************************************
// *****************************************************************************
// Section: OTA update check with server, JSON content parsing
// *****************************************************************************
// *****************************************************************************

static bool SYS_OTA_Update_Check() {
    static int downloader_no_data_read_cnt = 0;
    switch (sys_otaData.update_check_state) {
        case SYS_OTA_UPDATE_CHECK_CNCT_TO_SRVR:
        {
            sys_otaData.otaUpdateCheckInProgress = true;
            memset(sys_otaData.json_buf, 0, SYS_OTA_JSON_FILE_MAXSIZE);
            SYS_CONSOLE_PRINT("SYS OTA : Connecting to server : %s\r\n",g_SysOtaConfig.json_url);
            downloader = DOWNLOADER_Open(g_SysOtaConfig.json_url);
            if (downloader == DRV_HANDLE_INVALID) {
                SYS_CONSOLE_PRINT("SYS OTA : Downloader open error \r\n");
                sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_DONE;
                sys_otaData.update_check_failed = true;
                break;
            }
            #ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_PRINT("SYS OTA : downloader_no_data_read_cnt : %d\r\n",downloader_no_data_read_cnt);
            #endif
            sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_READ_JSON;
            break;
        }

        case SYS_OTA_UPDATE_CHECK_READ_JSON:
        {
            int rx_len = 0;
            static int rx_len_l = 0;
            if (SYS_OTA_ConnectedToNtwrk() == true) {
                rx_len = DOWNLOADER_Read(downloader, (uint8_t*) & sys_otaData.json_buf[0 + rx_len_l], (SYS_OTA_JSON_FILE_MAXSIZE - 10) - rx_len_l);
                if (downloader_no_data_read_cnt >= MAX_DOWNLOADER_READ_COUNT) {
                    if (downloader != DRV_HANDLE_INVALID) {
                        downloader_no_data_read_cnt = 0;
                        DOWNLOADER_Close(downloader);
                        downloader = DRV_HANDLE_INVALID;
                    }
                    sys_otaData.update_check_failed = true;
                    sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_DONE;
                    break;
                }
                if (rx_len <= 0) {
                    downloader_no_data_read_cnt++;
                    if (rx_len < 0) {
                        if (downloader != DRV_HANDLE_INVALID) {
                            downloader_no_data_read_cnt = 0;
                            DOWNLOADER_Close(downloader);
                            downloader = DRV_HANDLE_INVALID;
                        }
                        sys_otaData.update_check_failed = true;
                        sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_DONE;
                    }
                    break;
                }
                rx_len_l += rx_len;
                if(rx_len_l<field_content_length)
                    break;
                sys_otaData.json_buf[rx_len_l + 1] = '\0';
                #ifdef SYS_OTA_APPDEBUG_ENABLED
                SYS_CONSOLE_PRINT("SYS OTA : downloader_no_data_read_cnt : %d\r\n",downloader_no_data_read_cnt);
                #endif
                downloader_no_data_read_cnt = 0;
                sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_JSON_CONTENT;
                rx_len_l = 0;
            }
            break;
        }

        case SYS_OTA_UPDATE_CHECK_JSON_CONTENT:
        {
            SYS_CONSOLE_PRINT("SYS_OTA : JSON parsing \r\n");
            cJSON *config_json = OTA_cJSON_Parse(sys_otaData.json_buf);
            if (config_json == NULL) {
                OTA_cJSON_Delete(config_json);
                if (downloader != DRV_HANDLE_INVALID) {
                    DOWNLOADER_Close(downloader);
                    downloader = DRV_HANDLE_INVALID;
                }
                sys_otaData.update_check_failed = true;
                sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_DONE;
                break;
            }
            sys_otaData.json_content_parse_result = SYS_OTA_ParseJsonContent(config_json);
 
            /* Initialize File Download Parameters */
            if( (sys_otaData.update_check_state != SYS_OTA_DOWNLOAD_FILES) 
                    || (SYS_OTA_FILE_Params_Initialize() == false))
            {
				OTA_cJSON_Delete(config_json);
                sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_DONE;
            }
            break;

        }

        case SYS_OTA_DOWNLOAD_FILES:
        {
            if(g_SysFileData.error != true)
            {
                SYS_OTA_File_Download_Tasks();
                break;
            }
            SYS_CONSOLE_PRINT(TERM_RED"DOWNLOAD TASK ERROR(1)\r\n"TERM_RESET);
        }

        case SYS_OTA_UPDATE_CHECK_DONE:
        {
            sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_CNCT_TO_SRVR;
            sys_otaData.otaUpdateCheckInProgress = false;
            if (downloader != DRV_HANDLE_INVALID) {
                DOWNLOADER_Close(downloader);
                downloader = DRV_HANDLE_INVALID;
            }
            if (sys_otaData.json_content_parse_result == true)
                return true;
            break;
        }

            /* The default state should never be executed. */
        default:
        {
            return false;
            /* TODO: Handle error in application's state machine. */
            break;
        }
    }
    return false;
}
#ifdef SYS_OTA_CLICMD_ENABLED

static void SYS_OTA_Command_Process(int argc, char *argv[]) {

    if (g_u32SysOtaInitDone == 0) {
        SYS_CONSOLE_PRINT("\n\n\rOta Service Not Initialized");
    }
    if ((argc >= 2) && (!strcmp((char*) argv[1], "set"))) {
        if (((argv[2] == NULL)) || (!strcmp("?", argv[2]))) {
            SYS_CONSOLE_PRINT("\n\rFollowing commands supported");
            SYS_CONSOLE_PRINT("\n\r\t* sysota set <periodic check> <auto reset>  <auto update> <periodic interval> <url> ");
            SYS_CONSOLE_PRINT("\n\r\t* periodic check\t\t- 0 (disable)/ 1 (enable)");
            SYS_CONSOLE_PRINT("\n\r\t* auto reset\t\t\t- 0 (disable)/ 1 (enable)");
            SYS_CONSOLE_PRINT("\n\r\t* auto update\t\t\t- 0 (disable)/ 1 (enable)");
            SYS_CONSOLE_PRINT("\n\r\t* periodic interval\t\t- n second");
            SYS_CONSOLE_PRINT("\n\r\t* server url  \t\t\t- http://<server addr>//<file name>");
        }else if((argc == 5) && (!strcmp((char*) argv[2], "factory")) && (!strcmp((char*) argv[3], "sign"))){
            #ifdef SYS_OTA_SECURE_BOOT_ENABLED
            strcpy(g_SysOtaConfig.factory_image_signature,argv[4]);
            SYS_OTA_StoreFactoryImageSignature(g_SysOtaConfig.factory_image_signature);
            #else
            SYS_CONSOLE_PRINT("\n\rSecure OTA is not enabled\n\r");
            #endif
        }
        else {

            g_SysOtaConfig.ota_periodic_check = strtoul(argv[2], 0, 10);
            SYS_CONSOLE_PRINT("\n\rperiodic check : %d\n\r", g_SysOtaConfig.ota_periodic_check);

            if (argv[3] != NULL) {
                g_SysOtaConfig.autoreset = strtoul(argv[3], 0, 10);
                SYS_CONSOLE_PRINT("\n\rauto reset : %d\n\r", g_SysOtaConfig.autoreset);
            }

            if (argv[4] != NULL) {
                g_SysOtaConfig.ota_auto_update = strtoul(argv[4], 0, 10);
                SYS_CONSOLE_PRINT("\n\rauto update : %d\n\r", g_SysOtaConfig.ota_auto_update);
            }

            if (argv[5] != NULL) {
                g_SysOtaConfig.periodic_check_interval = strtoul(argv[5], 0, 10);
                SYS_CONSOLE_PRINT("\n\rperiodic interval : %d\n\r", g_SysOtaConfig.periodic_check_interval);
            }

            if (argv[6] != NULL) {
                strcpy(g_SysOtaConfig.json_url_cli,argv[6]);
                g_SysOtaConfig.json_url = g_SysOtaConfig.json_url_cli;
                SYS_CONSOLE_PRINT("\n\rjson url : %s\n\r", g_SysOtaConfig.json_url);
            }
        }
    }
    else if ((argc >= 2) && (!strcmp((char*) argv[1], "get"))){
        if(argv[2] == NULL){
            SYS_CONSOLE_PRINT("Following Command supported : \n\r");
            SYS_CONSOLE_PRINT("sysota get info \n\r");
        }
        else{
            if((!strcmp((char*) argv[2], "info"))){
                OTA_GetDownloadStatus(&ota_params);
#ifdef SYS_OTA_PATCH_ENABLE                
                OTA_GetPatchStatus(&ota_params);
#endif
                SYS_CONSOLE_PRINT("*******************************************\n\r");
                SYS_CONSOLE_PRINT("Status: %s\n\r", SYS_OTA_GET_STATUS_STR(sys_otaData.ota_srvc_status));
                SYS_CONSOLE_PRINT("Total data to download : %d bytes\n\r", ota_params.server_image_length);
                SYS_CONSOLE_PRINT("Data downloaded : %d bytes \r\n", ota_params.total_data_downloaded);
#ifdef SYS_OTA_PATCH_ENABLE
                SYS_CONSOLE_PRINT("Patch progress : %d percent \r\n", ota_params.patch_progress_status);
#endif
                SYS_CONSOLE_PRINT("Json-server url : %s\n\r", g_SysOtaConfig.json_url);
                SYS_CONSOLE_PRINT("Periodic check : %d (1=Enable, 0=Disable )\n\r", g_SysOtaConfig.ota_periodic_check);
                SYS_CONSOLE_PRINT("Periodic interval : %d sec\n\r", g_SysOtaConfig.periodic_check_interval);
                SYS_CONSOLE_PRINT("Auto reset : %d (0=disable)/ 1=enable)\n\r", g_SysOtaConfig.autoreset);
                SYS_CONSOLE_PRINT("*******************************************\n\r");
            }
            else{
                SYS_CONSOLE_PRINT("Following Command supported : \n\r");
                SYS_CONSOLE_PRINT("sysota get info \n\r");
            }
        }
    } 
    else if ((argc >= 2) && (!strcmp((char*) argv[1], "getfs"))){
        if(argv[2] == NULL){
            SYS_CONSOLE_PRINT("Following Command supported : \n\r");
            SYS_CONSOLE_PRINT("sysota get info \n\r");
        }
        else{
            if((!strcmp((char*) argv[2], "info"))){
				SYS_CONSOLE_PRINT("External Memory is not in use \n\r");
			
            }
            else{
                SYS_CONSOLE_PRINT("Following Command supported : \n\r");
                SYS_CONSOLE_PRINT("sysota getfs info \n\r");
            }
        }
    } 
    else{
        SYS_CONSOLE_PRINT("\n\rFollowing commands supported");
        SYS_CONSOLE_PRINT("\n\r\t1. sysota set <periodic check> <auto reset>  <auto update> <periodic interval> <url> ");
        SYS_CONSOLE_PRINT("\n\r\t\t* periodic check\t\t- 0 (disable)/ 1 (enable)");
        SYS_CONSOLE_PRINT("\n\r\t\t* auto reset\t\t\t- 0 (disable)/ 1 (enable)");
        SYS_CONSOLE_PRINT("\n\r\t\t* auto update\t\t\t- 0 (disable)/ 1 (enable)");
        SYS_CONSOLE_PRINT("\n\r\t\t* periodic interval\t\t- n second");
        SYS_CONSOLE_PRINT("\n\r\t\t* server url  \t\t\t- http://<server addr>//<file name>");

        SYS_CONSOLE_PRINT("\n\r\t2. sysota get info\n\r");
        
        SYS_CONSOLE_PRINT("\n\r\t3. sysota getfs info\n\r");
    }
}

static int SYS_OTA_CMDProcessing(SYS_CMD_DEVICE_NODE* pCmdIO, int argc, char** argv) \
            {
    SYS_OTA_Command_Process(argc, argv);
    return 0;
}

static int SYS_OTA_CMDHelp(SYS_CMD_DEVICE_NODE* pCmdIO, int argc, char** argv) {
    SYS_CONSOLE_PRINT("\n\rFollowing commands supported");
    SYS_CONSOLE_PRINT("\n\r\t1. sysota set <periodic check> <auto reset>  <auto update> <periodic interval> <url> ");
    SYS_CONSOLE_PRINT("\n\r\t\t* periodic check\t\t- 0 (disable)/ 1 (enable)");
    SYS_CONSOLE_PRINT("\n\r\t\t* auto reset\t\t\t- 0 (disable)/ 1 (enable)");
    SYS_CONSOLE_PRINT("\n\r\t\t* auto update\t\t\t- 0 (disable)/ 1 (enable)");
    SYS_CONSOLE_PRINT("\n\r\t\t* periodic interval\t\t- n second");
    SYS_CONSOLE_PRINT("\n\r\t\t* server url  \t\t\t- http://<server addr>//<file name>");
    
    SYS_CONSOLE_PRINT("\n\r\t2. sysota get info");
    SYS_CONSOLE_PRINT("\n\r\t3. sysota set factory sign <signature> ");
    return 0;
}
static const SYS_CMD_DESCRIPTOR g_SysOtaCmdTbl[] = {
    {"sysota", (SYS_CMD_FNC) SYS_OTA_CMDProcessing, ": SysOta commands processing"},
    {"sysotahelp", (SYS_CMD_FNC) SYS_OTA_CMDHelp, ": SysOta commands help "},
};

/******************************************************************/
#endif

// *****************************************************************************
// *****************************************************************************
// Section: To register user call back function
// *****************************************************************************
// *****************************************************************************

static inline SYS_OTA_RESULT SYS_OTA_REGCB(SYS_OTA_CALLBACK callback) {
    SYS_OTA_RESULT ret = SYS_OTA_FAILURE;

    if (!g_otaSrvcCallBack) {
        /* Copy the client function pointer */
        g_otaSrvcCallBack = callback;
        ret = SYS_OTA_SUCCESS;

    }

    return ret;
}

// *****************************************************************************
// *****************************************************************************
// Section:  SYS OTA Control Message Interface
// *****************************************************************************
// *****************************************************************************

SYS_OTA_RESULT SYS_OTA_CtrlMsg(uint32_t event, void *buffer, uint32_t length) {
    uint8_t ret = SYS_OTA_FAILURE;
    switch (event) {
        case SYS_OTA_REGCALLBACK:
        {
            SYS_OTA_CALLBACK g_otaSrvcFunPtr = buffer;
            if ((g_otaSrvcFunPtr) && (length == sizeof (g_otaSrvcFunPtr))) {
                /* Register the client callback function */
                ret = SYS_OTA_REGCB(g_otaSrvcFunPtr);
            }
            break;
        }
        case SYS_OTA_UPDATECHCK:
        {
            if (sys_otaData.state == SYS_OTA_STATE_IDLE) {
                sys_otaData.state = SYS_OTA_SERVER_UPDATE_CHECK;
                ret = SYS_OTA_SUCCESS;
            }
            break;
        }
        case SYS_OTA_INITIATE_OTA:
        {
            if (sys_otaData.state == SYS_OTA_STATE_IDLE) {
                sys_otaData.state = SYS_OTA_TRIGGER_OTA;
                ret = SYS_OTA_SUCCESS;
            }
            break;
        }
        case SYS_OTA_TRIGGER_SYSTEM_RESET:
        {
            if (sys_otaData.state == SYS_OTA_STATE_IDLE) {
                sys_otaData.state = SYS_OTA_SYSTEM_RESET;
                ret = SYS_OTA_SUCCESS;
            }
			break;
        }
        case SYS_OTA_TRIGGER_FACTORY_RESET:
        {
            if (sys_otaData.state == SYS_OTA_STATE_IDLE) {
                sys_otaData.state = SYS_OTA_FACTORY_RESET;
                ret = SYS_OTA_SUCCESS;
            }
			break;
        }
        case SYS_OTA_TRIGGER_ROLLBACK:
        {
            if (sys_otaData.state == SYS_OTA_STATE_IDLE) {
                sys_otaData.state = SYS_OTA_ROLLBACK;
                ret = SYS_OTA_SUCCESS;
            }
			break;
        }
    }

    return ret;
}


// *****************************************************************************
// *****************************************************************************
// Section: To set OTA image related parameters 
// *****************************************************************************
// *****************************************************************************
void SYS_OTA_SET_PARAMETERS(char *url, uint32_t version, char *digest)
{
    memcpy(ota_params.ota_server_url, url, strlen(url) + 1);
    ota_params.version = version;
    strncpy(ota_params.serv_app_digest_string, digest, 64);
}

// *****************************************************************************
// *****************************************************************************
// Section: To trigger system reset
// *****************************************************************************
// *****************************************************************************

void SYS_OTA_SystemReset(void) {
    SYSKEY = 0x00000000;
    SYSKEY = 0xAA996655;
    SYSKEY = 0x556699AA;
    RSWRSTSET = _RSWRST_SWRST_MASK;

    RSWRST;

    Nop();
    Nop();
    Nop();
    Nop();
}

// *****************************************************************************
// *****************************************************************************
// Section: OTA_RTCC callback function
// *****************************************************************************
// *****************************************************************************

void OTA_RTCC_Callback(uintptr_t context) {
    sys_otaData.ota_timer_trigger = true;
}

// *****************************************************************************
// *****************************************************************************
// Section: Setting RTCC Alarm 
// *****************************************************************************
// *****************************************************************************

static void SYS_OTA_RTCset(void) {
    struct tm sys_time;
    struct tm alarm_time;

    uint32_t n = g_SysOtaConfig.periodic_check_interval;
    //    uint32_t day = n / (24 * 3600);

    n = n % (24 * 3600);
    uint32_t hour = n / 3600;

    n %= 3600;
    uint32_t minutes = n / 60;

    n %= 60;
    uint32_t seconds = n;

    // Time setting 31-12-2018 23:59:58 Monday
    sys_time.tm_hour = 23;
    sys_time.tm_min = 59;
    sys_time.tm_sec = 58;

    sys_time.tm_year = 18;
    sys_time.tm_mon = 12;
    sys_time.tm_mday = 31;
    sys_time.tm_wday = 1;

    // Alarm setting 01-01-2019 00:00:05 Tuesday
    alarm_time.tm_hour = hour;
    alarm_time.tm_min = minutes;
    alarm_time.tm_sec = seconds;

    alarm_time.tm_year = 19;
    alarm_time.tm_mon = 01;
    alarm_time.tm_mday = 01;
    alarm_time.tm_wday = 2;

    RTCC_TimeSet(&sys_time);
    RTCC_AlarmSet(&alarm_time, RTCC_ALARM_MASK_HHMISS);
    RTCC_TimeGet(&sys_time);
}


// *****************************************************************************
// *****************************************************************************
// Section: File/Img download functions definition 
// *****************************************************************************
// *****************************************************************************/
/******************************************************************************/
/* Initialize the parameters required for file download*/
static bool SYS_OTA_FILE_Params_Initialize
(
    void
)
{
    g_SysFileData.error = false;
    
    if (SYS_OTA_NUM_OF_SLOTS <= 0)
    {
        return false;
    }
    
    g_SysFileData.file_index = 0;
    
    /* Calculate the address of Slots */
			g_SysFileData.slot_info.slot_size[0] = (uint32_t )SYS_OTA_SLOT_0_SIZE;
    g_SysFileData.slot_info.slot_address[0] = SYS_OTA_FILE_DOWNLOAD_START_ADDRESS;

    for(int i=1; i < SYS_OTA_NUM_OF_SLOTS; i++){
        g_SysFileData.slot_info.slot_address[i] = g_SysFileData.slot_info.slot_address[i-1] 
                + g_SysFileData.slot_info.slot_size[i-1];
    }
    return true;
}

/* Parse JSON content for Server Files data*/
static bool SYS_OTA_Parse_JSON
(
    uint8_t index
)
{
    bool download_start = false;
    cJSON *config_json = OTA_cJSON_Parse(sys_otaData.json_buf);
    if (config_json == NULL) {
        OTA_cJSON_Delete(config_json);
        g_SysFileData.error = true;
        return false;
    }
    
    cJSON *server_array = OTA_cJSON_GetObjectItem(config_json, "ota");
    uint8_t server_array_count = OTA_cJSON_GetArraySize(server_array);
        
    /* To find the Files array in Json file, if present parse the file and save in array */
    cJSON *temp_array = NULL,*files_array = NULL;
    for(int array_count=0; array_count < server_array_count; array_count++)
    {
        temp_array = OTA_cJSON_GetArrayItem(server_array,array_count);
        files_array = OTA_cJSON_GetObjectItem(temp_array, "files");
        if(files_array != NULL)
        {
            //SYS_CONSOLE_PRINT("SYS_OTA_FILE : Downloading index : %d\r\n",index);
            download_start = true;
            break;
        }
    }
    if (files_array == NULL)
    {
        return false;
    }
    
#ifdef SYS_OTA_APPDEBUG_ENABLED
    SYS_CONSOLE_PRINT("SYS_OTA_FILE : Total Number of Files to be Downloaded : %d\r\n",g_SysFileData.total_no_of_files);
    SYS_CONSOLE_PRINT("SYS_OTA_FILE : Downloading index : %d",index);
#endif
    
    cJSON *file_data = OTA_cJSON_GetArrayItem(files_array,index);
    
    if( download_start == true && SYS_OTA_Get_File_Data(file_data))
    {
         return true;;
    }
    return false;
}

/* Get Key data from server */
static bool SYS_OTA_Get_Key_Data
(
    cJSON *cert_data
)
{
    cJSON *slot_number = OTA_cJSON_GetObjectItem(cert_data, "slot_number");
    cJSON *file_size = OTA_cJSON_GetObjectItem(cert_data,"length");
    cJSON *file_URL = OTA_cJSON_GetObjectItem(cert_data,"URL");
    /* ERROR Handling*/
    if( slot_number == NULL || file_size == NULL
            || file_URL == NULL)
    {
        return false;
    }
    g_SysFileData.slot_number = (uint8_t) slot_number->valueint;
    /* ERROR Handling */
    if(g_SysFileData.slot_number >= SYS_OTA_NUM_OF_SLOTS 
            || g_SysFileData.slot_number < 0)
    {
       SYS_CONSOLE_PRINT("\tERROR!!! - Slot Number \r\n");
       return false;
    } 
    g_public_key_slot = g_SysFileData.slot_number;
    /* ERROR Handling *//* To check if file size is greater than slot size*/
    if((uint32_t) file_size->valueint 
            > g_SysFileData.slot_info.slot_size[g_SysFileData.slot_number])
    {
       SYS_CONSOLE_PRINT("\tERROR!!! - Slot Size \r\n");
       return false;
    }
        
    g_SysFileData.slot_info.file_size_in_slot[g_SysFileData.slot_number] = (uint32_t) file_size->valueint;
    /* Copy file URL  and digest  */
    memset(g_SysFileData.file_url,'\0', OTA_URL_SIZE);
    memcpy(g_SysFileData.file_url, (char *)file_URL->valuestring, strlen(file_URL->valuestring));
	

    g_key_present = true;
    g_secure_download = true;
    return true;
}        
    
    
/* Get each file array data into structure */
static bool SYS_OTA_Get_File_Data
(
    cJSON *file_data
)
{
    
    if (g_key_present == false)
    {
        cJSON *cert_array = OTA_cJSON_GetObjectItem(file_data, "public_key");
        
        if( cert_array != NULL)
        {
            
            cJSON *cert_data = OTA_cJSON_GetArrayItem(cert_array,0);
            return SYS_OTA_Get_Key_Data(cert_data);
        }
    }
    
    g_key_present = false;
    cJSON *slot_number = OTA_cJSON_GetObjectItem(file_data, "slot_number");
    cJSON *file_size = OTA_cJSON_GetObjectItem(file_data,"length");
    cJSON *file_URL = OTA_cJSON_GetObjectItem(file_data,"URL");
    

    /* ERROR Handling*/
    if( slot_number == NULL || file_size == NULL
            || file_URL == NULL)
    {
        return false;
    }
    g_SysFileData.slot_number = (uint8_t) slot_number->valueint;
    /* ERROR Handling */
    if(g_SysFileData.slot_number >= SYS_OTA_NUM_OF_SLOTS 
            || g_SysFileData.slot_number < 0)
    {
       return false;
    } 
    /* ERROR Handling *//* To check if file size is greater than slot size*/
    if((uint32_t) file_size->valueint 
            > g_SysFileData.slot_info.slot_size[g_SysFileData.slot_number])
    {
       return false;
    }
        
    g_SysFileData.slot_info.file_size_in_slot[g_SysFileData.slot_number] = (uint32_t) file_size->valueint;
    /* Copy file URL  and digest  */
    memset(g_SysFileData.file_url,'\0', OTA_URL_SIZE);
    memcpy(g_SysFileData.file_url, (char *)file_URL->valuestring, strlen(file_URL->valuestring));
 
    

    return true;
}        

/* To Read from NVM */
static bool SYS_OTA_NVM_Read
(
    uint32_t addr, 
    uint8_t* buff, 
    uint32_t len
)
{
    INT_Flash_Open();
    
    if(INT_Flash_Read(addr, buff, len)){
        INT_Flash_Close();
        return true;
    }
    return false;
}

/* To Write to NVM */
static bool SYS_OTA_NVM_Write
(
    uint32_t addr, 
    uint8_t* buff, 
    uint32_t len
)
{
    INT_Flash_Open();
    
    /* Erase cycle is always 4KB aligned*/
    if(INT_Flash_Erase(addr, 4096U)){
        if(INT_Flash_Write(addr, buff, len)){
            INT_Flash_Close();
            return true;
        }
    } 
    return false;
}

/* To check the Slot */
static bool SYS_OTA_CheckSlot
(
    int slot_number
)
{
    uint32_t addr = g_SysFileData.slot_info.slot_address[slot_number];
    uint32_t size = g_SysFileData.slot_info.slot_size[slot_number];
    uint8_t buf[1024] = {0};
    uint8_t erase_flag = 0xFF;
    
    for(int i = 0; i < size; i += 1024 ){
        while(NVM_IsBusy());
        SYS_OTA_NVM_Read(addr, buf, 1024);
        for(int j = 0; j < 1024; j++){
            if(buf[j] != erase_flag){
                #ifdef SYS_OTA_APPDEBUG_ENABLED
                SYS_CONSOLE_PRINT("\tSlot %d IS not Empty\r\n");
                #endif
                return false;
            }
        }
        addr += 1024;
    }
    #ifdef SYS_OTA_APPDEBUG_ENABLED
        SYS_CONSOLE_PRINT(TERM_GREEN"\tSlot %d Empty -> Download\r\n"TERM_RESET);
    #endif
    return true;
}

 
 /* To download file from Server*/
 static bool SYS_OTA_Download_File
 (
    char *file_URL
 )
 {
    int rx_len = 0;
    static OTA_FILE_DOWNLOAD_TASK_CONTEXT cntx;
    static SYS_OTA_FILE_DOWNLOAD_STATE download_status = SYS_OTA_FILE_OPEN;
    static DRV_HANDLE downloader2;
    static uint32_t Slot_address = 0;
    
    switch (download_status) {
        case SYS_OTA_FILE_OPEN:
        {
            cntx.buf_len = 0; 
            cntx.copied_len = 0;
            cntx.total_len = g_SysFileData.slot_info.file_size_in_slot[g_SysFileData.slot_number];
            field_content_length = 0;
            
			/* Create the buffer */
            cntx.buf = (uint8_t *)OSAL_Malloc(FLASH_SECTOR_SIZE);
            if(cntx.buf == NULL){
                g_SysFileData.error = true; 
                break;
            }
            downloader2 = DOWNLOADER_Open(file_URL);
            if (downloader2 == DRV_HANDLE_INVALID) {
                SYS_CONSOLE_PRINT(TERM_RED"SYS_OTA_FILE_ERROR : Unable to open File URL \r\n"TERM_RESET);
                g_SysFileData.error = true;
                break;
            }
			
            Slot_address = g_SysFileData.slot_info.slot_address[g_SysFileData.slot_number];
            SYS_CONSOLE_PRINT("FILE: %d -> Downloading to Slot : %d Address : %X Total_len : %d\r\n",g_SysFileData.file_index,g_SysFileData.slot_number,Slot_address, g_SysFileData.slot_info.file_size_in_slot[g_SysFileData.slot_number]);
            download_status = SYS_OTA_FILE_DOWNLOAD;
            break;
        }
        
        case SYS_OTA_FILE_DOWNLOAD:
        {
            int req_len = cntx.total_len - cntx.copied_len;
            if (req_len > FLASH_SECTOR_SIZE) {
                req_len = FLASH_SECTOR_SIZE;
            }
            /* Download 4KB of file (if file size is more than 4KB)*/
            rx_len = DOWNLOADER_Read(downloader2, &cntx.buf[cntx.buf_len], ( req_len - cntx.buf_len )); 
            #ifdef SYS_OTA_APPDEBUG_ENABLED
            if(rx_len != 0){
                SYS_CONSOLE_PRINT("\tTASK_STATE_D_DOWNLOAD :: rx_len : %d\r\n",rx_len);
            }
            #endif
            if (rx_len <= 0) {
                if (rx_len < 0) {
                    g_SysFileData.error = true;
                    SYS_CONSOLE_PRINT(TERM_RED"\tSYS OTA FILE ERROR : File Downloading error\r\n"TERM_RESET);
                }
                break;
            }
            cntx.buf_len += rx_len;
            if(field_content_length != 0)
            {
                cntx.total_len = field_content_length;
                g_SysFileData.slot_info.file_size_in_slot[g_SysFileData.slot_number] = field_content_length;
                /*To Check if actual size of file is greater than slot size */
                if(field_content_length > g_SysFileData.slot_info.slot_size[g_SysFileData.slot_number]){
                    SYS_CONSOLE_PRINT(TERM_RED"\tOriginal File size is Greater than slot size\r\n"TERM_RESET);
                    g_SysFileData.error = true;
                    break;
                }
            }
            
            /* Stop download when buffer is full */
            if (cntx.buf_len == req_len) {
                download_status = SYS_OTA_FILE_WRITE_TO_NVM;
            }
            break;
        }
		 
		 /*Write to NVM */
        case SYS_OTA_FILE_WRITE_TO_NVM:
        {
            /* Write 4KB of file to NVM*/
            while(NVM_IsBusy());
            if(SYS_OTA_NVM_Write (Slot_address, cntx.buf, FLASH_SECTOR_SIZE ) != true ){
                SYS_CONSOLE_PRINT(TERM_RED"\tNVM Write Error \r\n"TERM_RESET);
                g_SysFileData.error = true;
                break;
            }
            
            cntx.copied_len += cntx.buf_len;
            cntx.buf_len = 0;
           
            if(cntx.copied_len < cntx.total_len){
                download_status = SYS_OTA_FILE_DOWNLOAD;
                Slot_address += FLASH_SECTOR_SIZE;
                break;
            }
            download_status = SYS_OTA_FILE_DOWNLOAD_DONE;
            break;
        }
        
        case SYS_OTA_FILE_DOWNLOAD_DONE:
        {
            DOWNLOADER_Close(downloader2);
            SYS_CONSOLE_PRINT("\tDownloaded length %d\r\n",g_SysFileData.slot_info.file_size_in_slot[g_SysFileData.slot_number]);
            
            OSAL_Free(cntx.buf);
            cntx.buf = NULL;
            download_status = SYS_OTA_FILE_OPEN;
			File_Dnld_Status = SYS_OTA_PARSE_JSON;
			g_SysFileData.file_index++;
            break;
        }
    }
    return false;
}     
 
 void SYS_OTA_Print_Server_Data(void)
 {
    SYS_CONSOLE_PRINT("\nslot : %d\r\n",g_SysFileData.slot_number);
    SYS_CONSOLE_PRINT("length : %d\r\n",g_SysFileData.slot_info.file_size_in_slot[g_SysFileData.slot_number]);
    SYS_CONSOLE_PRINT("URL : %s\r\n",g_SysFileData.file_url);
    SYS_CONSOLE_PRINT("digest : \r\n");
    for(int i = 0; i < 64; i++){
        SYS_CONSOLE_PRINT("%c",g_SysFileData.file_digest_string[i]);
    }
    SYS_CONSOLE_PRINT("\nsign : \r\n");
    for(int i = 0; i < 98; i++){
        SYS_CONSOLE_PRINT("%c",g_SysFileData.file_signature_string[i]);
    }
    
 }
 
 /* File Download Tasks*/
static void SYS_OTA_File_Download_Tasks
(
    void
)
{
    g_SysFileData.error = false;
    
    switch(File_Dnld_Status)
    {
        case SYS_OTA_PARSE_JSON:
            if (g_SysFileData.file_index < g_SysFileData.total_no_of_files )
            {
                if( !(SYS_OTA_Parse_JSON(g_SysFileData.file_index)))
                {
                    SYS_CONSOLE_PRINT(TERM_RED"\tJSON Parse Error \r\n"TERM_RESET);
                    g_SysFileData.error = true;
                    break;
                }
                File_Dnld_Status = SYS_OTA_CHECK_SLOT;
                break;
            }
            
            File_Dnld_Status = SYS_OTA_DOWNLOAD_DONE;
            break;
            
        case SYS_OTA_CHECK_SLOT:
        {
            if( SYS_OTA_CheckSlot(g_SysFileData.slot_number))
            {
                /* if Slot empty Download file*/
                File_Dnld_Status = SYS_OTA_DOWNLOAD_FILE;
                break;
            }
            
            /* If Slot not empty, Check if its key slot*/
            if(g_public_key_slot == g_SysFileData.slot_number)
            {
                File_Dnld_Status = SYS_OTA_PARSE_JSON;
                break;
            }
			File_Dnld_Status = SYS_OTA_DOWNLOAD_FILE;
            break;
        }
        case SYS_OTA_DOWNLOAD_FILE:
            if(g_SysFileData.error == false)
            {
                SYS_OTA_Download_File(g_SysFileData.file_url);
                break;
            }
            break;
        case SYS_OTA_DOWNLOAD_DONE:
        {
            SYS_CONSOLE_PRINT(TERM_GREEN"SYS_OTA_FILE : Files Downloaded Successfully\r\n"TERM_RESET);
            g_SysFileData.error = false;
            g_SysFileData.file_index = 0;
			File_Dnld_Status = SYS_OTA_PARSE_JSON;
            File_Dnld_Status = SYS_OTA_UPDATE_BOOTCNTRL_AREA;
            break;
        }
   
        case SYS_OTA_UPDATE_BOOTCNTRL_AREA:
        {
            OTA_UpdateBootctl();
            break;
        }
        case SYS_OTA_FILE_DOWNLOAD_ERROR:
            SYS_CONSOLE_PRINT(TERM_RED"SYS_OTA_FILE : DOWNLOAD_ERROR \r\n"TERM_RESET);
			g_SysFileData.file_index = 0;
            File_Dnld_Status = SYS_OTA_PARSE_JSON;
            sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_DONE;
            g_SysFileData.error = true;
            break;
            
    }
    return;
}

// *****************************************************************************
// *****************************************************************************
// Section: Initialization of OTA service related parameters
// *****************************************************************************
// *****************************************************************************/

void SYS_OTA_Initialize(void) {

    memset(&sys_otaData, 0, sizeof (sys_otaData));
    sys_otaData.state = SYS_OTA_REGWIFISRVCALLBCK;
    sys_otaData.update_check_state = SYS_OTA_UPDATE_CHECK_CNCT_TO_SRVR;

    CRYPT_RNG_CTX * rng_context;
    /*Initialize PRNG for SYS_RANDOM_PseudoGet().*/
    rng_context = OSAL_Malloc(sizeof (CRYPT_RNG_CTX));
    if (rng_context != NULL) {
        if (CRYPT_RNG_Initialize(rng_context) == 0) {
            uint32_t rng;
            CRYPT_RNG_BlockGenerate(rng_context, (unsigned char*) &rng, sizeof (rng));
            srand(rng);
        }
        OSAL_Free(rng_context);
    }

    HTTP_Client_Init();
    g_SysOtaConfig.ota_periodic_check = SYS_OTA_PERODIC_UPDATE;
    g_SysOtaConfig.ota_auto_update = SYS_OTA_AUTOUPDATE_ENABLE;
    g_SysOtaConfig.app_version = SYS_OTA_APP_VER_NUM;
    g_SysOtaConfig.periodic_check_interval = SYS_OTA_TIME_INTERVAL;
    g_SysOtaConfig.autoreset = SYS_OTA_AUTORESET_ENABLE;
    g_SysOtaConfig.json_url = SYS_OTA_URL;
    RTCC_CallbackRegister(OTA_RTCC_Callback, (uintptr_t) NULL);
#ifdef SYS_OTA_CLICMD_ENABLED
    /* Add Sys OTA Commands to System Command service */
    if (!SYS_CMD_ADDGRP(g_SysOtaCmdTbl, sizeof (g_SysOtaCmdTbl) / sizeof (*g_SysOtaCmdTbl), "sysota", ": Sys OTA commands")) {
        SYS_CONSOLE_MESSAGE("SYS OTA : Failed to Initialize Service as SysOta Commands NOT created\r\n");
        //        return SYS_NET_FAILURE;
    }
    g_u32SysOtaInitDone = 1;
#endif
}

// *****************************************************************************
// *****************************************************************************
// Section: OTA System service task 
// *****************************************************************************
// *****************************************************************************/

void SYS_OTA_Tasks(void) {
    switch (sys_otaData.state) {
        case SYS_OTA_REGWIFISRVCALLBCK:
        {
            IPV4_ADDR ipAddr;
#if     SYS_OTA_INTF == SYS_OTA_ETHERNET
            TCPIP_NET_HANDLE netH = TCPIP_STACK_NetHandleGet("eth0");
#elif   SYS_OTA_INTF == SYS_OTA_WIFI
            TCPIP_NET_HANDLE netH = TCPIP_STACK_NetHandleGet("PIC32MZW1"); 
#endif
            ipAddr.Val = TCPIP_STACK_NetAddress(netH);

               if (ipAddr.Val)
                {
                SYS_CONSOLE_MESSAGE("\r\nSYS OTA : IP address obtained for preferred interface for OTA\r\n");
                sys_otaData.dev_cnctd_to_nw = true;
                sys_otaData.state = SYS_OTA_WAITFOR_NETWORK_CONNECTION;
            }
            break;
        }
        case SYS_OTA_WAITFOR_NETWORK_CONNECTION:
        {
            if (SYS_OTA_ConnectedToNtwrk() == true) {
                sys_otaData.state = SYS_OTA_WAITFOR_OTAIDLE;
                
            }
            SYS_OTA_SetOtaServicStatus(SYS_OTA_WAITING_FOR_NETWORK_CONNECTION);
            break;
        }
        case SYS_OTA_WAITFOR_OTAIDLE:
        {
            if (OTA_IsIdle() == true) {
                sys_otaData.state = SYS_OTA_REGOTACALLBCK;
            }
            SYS_OTA_SetOtaServicStatus(SYS_OTA_WAITING_FOR_OTACORE_IDLE);
            break;
        }
        case SYS_OTA_REGOTACALLBCK:
        {
            if (OTA_CallBackReg(_OTACallback, sizeof (uint8_t *)) == SYS_STATUS_ERROR) {
                SYS_CONSOLE_PRINT("SYS OTA : OTA callback register failed \r\n");
            } else {
                SYS_OTA_IsTls_Request(g_SysOtaConfig.json_url);
                sys_otaData.state = SYS_OTA_AUTO_CONFIGURATION_CHECK;
            }
            break;
        }
        case SYS_OTA_AUTO_CONFIGURATION_CHECK:
        {
            if (SYS_OTA_IsAutoUpdtChckEnbl() == true) {
                sys_otaData.time_interval = 0;
                SYS_OTA_RTCset();
                sys_otaData.state = SYS_OTA_WAIT_FOR_OTA_TIMER_TRIGGER;
            } else {
#ifdef  SYS_OTA_TLS_ENABLED
                if(sys_ota_tls == true){
                    uint32_t time = TCPIP_SNTP_UTCSecondsGet();
                    if (time == 0)
                    {
                        /* SNTP Time Stamp NOT Available */
                        break;
                    }
                }
#endif
                sys_otaData.state = SYS_OTA_STATE_IDLE;
            }
            break;
        }
        case SYS_OTA_WAIT_FOR_OTA_TIMER_TRIGGER:
        {
            SYS_OTA_SetOtaServicStatus(SYS_OTA_WAITING_FOR_USER_DEFINED_PERIOD);
            if (SYS_OTA_IsAutoUpdtChckEnbl() == false)
                break;
            if ((SYS_OTA_IsOtaTimerTriggered() == true)) {
                sys_otaData.ota_timer_trigger = false;
                sys_otaData.otaUpdateCheckInProgress = true; /*can be set to false only by SYS_OTA_Update_Check(), at the end of update check process*/
                sys_otaData.state = SYS_OTA_AUTO_UPDATE_CHECK;
                SYS_OTA_SetOtaServicStatus(SYS_OTA_UPDATE_CHECK_START);
                if (g_otaSrvcCallBack != NULL)
                    g_otaSrvcCallBack(sys_otaData.ota_srvc_status, NULL, NULL);
            }
            break;
        }
        case SYS_OTA_AUTO_UPDATE_CHECK:
        {
            if ((SYS_OTA_IsUpdateCheckInProgress() == false) && (SYS_OTA_IsEraseImageRequest() == false)) {
                if(sys_otaData.update_check_failed == true)
                {
                    SYS_OTA_SetOtaServicStatus(SYS_OTA_UPDATE_CHECK_FAILED);
                    if (g_otaSrvcCallBack != NULL)
                        g_otaSrvcCallBack(sys_otaData.ota_srvc_status, NULL, NULL);

                    sys_otaData.update_check_failed = false;
                }
                else
                {
                    SYS_OTA_SetOtaServicStatus(SYS_OTA_UPDATE_NOTAVAILABLE);
                    if (g_otaSrvcCallBack != NULL)
                        g_otaSrvcCallBack(sys_otaData.ota_srvc_status, NULL, NULL);
                }
                sys_otaData.state = SYS_OTA_WAIT_FOR_OTA_TIMER_TRIGGER;
                SYS_OTA_RTCset();
                break;
            }

            if ((SYS_OTA_IsOtaInProgress() == false) && (SYS_OTA_IsDownloadSuccess() == false)) {
                /*To check if New update available in server*/
                if (SYS_OTA_Update_Check()) {
                    /*provide callback to user about update availability*/
                    SYS_OTA_SetOtaServicStatus(SYS_OTA_UPDATE_AVAILABLE);
                    sys_otaData.state = SYS_OTA_UPDATE_USER;
                }
            }
            break;
        }
        case SYS_OTA_SERVER_UPDATE_CHECK:
        {
            sys_otaData.otaUpdateCheckInProgress = true;
            sys_otaData.state = SYS_OTA_SERVER_UPDATE_CHECK_TRIGGER;
            SYS_OTA_SetOtaServicStatus(SYS_OTA_UPDATE_CHECK_START);
            if (g_otaSrvcCallBack != NULL)
                g_otaSrvcCallBack(sys_otaData.ota_srvc_status, NULL, NULL);
            break;
        }
        case SYS_OTA_SERVER_UPDATE_CHECK_TRIGGER:
        {
            
            if ((SYS_OTA_IsOtaInProgress() == false) && (SYS_OTA_IsDownloadSuccess() == false)) {
                /*To check if New update available in server*/
                if (SYS_OTA_Update_Check()) {
                    /*provide callback to user about update availability*/
                    SYS_OTA_SetOtaServicStatus(SYS_OTA_UPDATE_AVAILABLE);
                    sys_otaData.state = SYS_OTA_UPDATE_USER;
                    break;
                }
            }
            if ((SYS_OTA_IsUpdateCheckInProgress() == false) && (SYS_OTA_IsEraseImageRequest() == false)) {
                if (sys_otaData.update_check_failed == true) {
                    SYS_OTA_SetOtaServicStatus(SYS_OTA_UPDATE_CHECK_FAILED);
                    if (g_otaSrvcCallBack != NULL)
                        g_otaSrvcCallBack(sys_otaData.ota_srvc_status, NULL, NULL);

                    sys_otaData.update_check_failed = false;
                } else {
                    SYS_OTA_SetOtaServicStatus(SYS_OTA_UPDATE_NOTAVAILABLE);
                    if (g_otaSrvcCallBack != NULL)
                        g_otaSrvcCallBack(sys_otaData.ota_srvc_status, NULL, NULL);
                }
                sys_otaData.state = SYS_OTA_STATE_IDLE;

                break;
            }
            break;
        }
        case SYS_OTA_TRIGGER_OTA:
        {
#ifdef  SYS_OTA_TLS_ENABLED
            if(SYS_OTA_IsTls_Request(ota_params.ota_server_url) == true){
                uint32_t time = TCPIP_SNTP_UTCSecondsGet();
                if (time == 0){
                    break;
                }
            }
#endif
            SYS_STATUS status;
            /*start OTA only if device connected to network, OTA is not already in progress, new image is not already downloaded*/
            if ((SYS_OTA_ConnectedToNtwrk() == true) && (SYS_OTA_IsOtaInProgress() == false) && (SYS_OTA_IsDownloadSuccess() == false)) {
                SYS_CONSOLE_PRINT("SYS OTA : Starting OTA with server: %s \r\n", ota_params.ota_server_url);
                status = OTA_Start(&ota_params);
                sys_otaData.otaFwInProgress = true;
                if (status == SYS_STATUS_ERROR) {
                    SYS_CONSOLE_PRINT("SYS OTA : Error starting OTA\r\n");
                    SYS_OTA_SetOtaServicStatus(SYS_OTA_TRIGGER_OTA_FAILED);
                    sys_otaData.state = SYS_OTA_UPDATE_USER;
                }
            }
            break;
        }
        case SYS_OTA_WAIT_FOR_OTA_COMPLETE:
        {
            /*wait for OTA complete*/
            break;
        }
        case SYS_OTA_ERASE_IMAGE:
        {
            if (SYS_OTA_IsOtaInProgress() == false) {
                OTA_EraseImage(ota_params.delete_img_version);
                sys_otaData.otaEraseInProgress = true;
            }
            break;
        }
        case SYS_OTA_FACTORY_RESET:
        {
            if (SYS_OTA_IsOtaInProgress() == false) {
                if (SYS_STATUS_ERROR == OTA_FactoryReset()) {
                    SYS_CONSOLE_PRINT("SYS OTA : Error Factory reset\r\n");
                    SYS_OTA_SetOtaServicStatus(SYS_OTA_FACTORY_RESET_FAILED);
                    sys_otaData.state = SYS_OTA_UPDATE_USER;
                }
            }
            sys_otaData.state = SYS_OTA_STATE_IDLE;
            break;
        }
        case SYS_OTA_ROLLBACK:
        {
            if ((SYS_OTA_IsOtaInProgress() == false) && ((SYS_OTA_IsDownloadSuccess() == false))) {
                if (SYS_STATUS_ERROR == OTA_Rollback()) {
                    SYS_CONSOLE_PRINT("SYS OTA :  Error Rollback\r\n");
                    SYS_OTA_SetOtaServicStatus(SYS_OTA_ROLLBACK_FAILED);
                    sys_otaData.state = SYS_OTA_UPDATE_USER;
                }
            } else {
                SYS_OTA_SetOtaServicStatus(SYS_OTA_ROLLBACK_FAILED);
                sys_otaData.state = SYS_OTA_UPDATE_USER;
            }
            sys_otaData.state = SYS_OTA_STATE_IDLE;
            break;
        }
        case SYS_OTA_UPDATE_USER:
        {
            sys_otaData.state = SYS_OTA_STATE_IDLE;
            
            if ((sys_otaData.ota_srvc_status == SYS_OTA_DOWNLOAD_START) || (sys_otaData.ota_srvc_status == SYS_OTA_DOWNLOAD_SUCCESS) || (sys_otaData.ota_srvc_status == SYS_OTA_IMAGE_DIGEST_VERIFY_START) || (sys_otaData.ota_srvc_status == SYS_OTA_IMAGE_DIGEST_VERIFY_SUCCESS))
                sys_otaData.state = SYS_OTA_WAIT_FOR_OTA_COMPLETE;
            
            if (sys_otaData.ota_srvc_status != SYS_OTA_NONE) {
                if (g_otaSrvcCallBack != NULL)
                    g_otaSrvcCallBack(sys_otaData.ota_srvc_status, NULL, NULL);
            }
            
            /*If image downloaded successfully*/
            if (SYS_OTA_IsDownloadSuccess() == true)
                sys_otaData.state = SYS_OTA_AUTORESET;
            
            /*If update available in server and auto update is enabled trigger ota */
            if (sys_otaData.ota_srvc_status == SYS_OTA_UPDATE_AVAILABLE) {
                if (SYS_OTA_IsAutoUpdtEnbl() == true)
                    sys_otaData.state = SYS_OTA_TRIGGER_OTA;
            }
            
            break;
        }
        case SYS_OTA_AUTORESET:
        {
#ifdef SYS_OTA_APPDEBUG_ENABLED
            SYS_CONSOLE_DEBUG1("SYS_OTA_AUTORESET");
#endif
            if (SYS_OTA_GetAutoReset()) {
                if (SYS_OTA_IsDownloadSuccess() == true) {
                    SYS_OTA_SystemReset();
                }
            } else {
                sys_otaData.state = SYS_OTA_STATE_IDLE;
            }
            break;
        }
        case SYS_OTA_SYSTEM_RESET:
        {
            if (SYS_OTA_IsDownloadSuccess() == true) {
                SYS_OTA_SystemReset();
            } else {
                SYS_CONSOLE_PRINT("SYS OTA : OTA DB entry is not yet done\n\r");
                sys_otaData.state = SYS_OTA_STATE_IDLE;
            }
            break;
        }
        case SYS_OTA_STATE_IDLE:
        {
            /*OTA system in idle state*/
            SYS_OTA_SetOtaServicStatus(SYS_OTA_IDLE);
            break;
        }
        default:
        {
            /* TODO: Handle error in application's state machine. */
            break;
        }
    }
    OTA_Tasks();
}


/*******************************************************************************
 End of File
 */
