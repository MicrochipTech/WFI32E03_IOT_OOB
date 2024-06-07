/*******************************************************************************
  Company:
    Microchip Technology Inc.

  File Name:
    ota.c
    
  Summary:
    Interface for the Bootloader library.

  Description:
    This file contains the interface definition for the OTA library.
 *******************************************************************************/

// DOM-IGNORE-BEGIN
/*******************************************************************************
Copyright (c) 2020-2021 released Microchip Technology Inc.  All rights reserved.

Microchip licenses to you the right to use, modify, copy and distribute
Software only when embedded on a Microchip microcontroller or digital signal
controller that is integrated into your product or third party product
(pursuant to the sublicense terms in the accompanying license agreement).

You should refer to the license agreement accompanying this Software for
additional information regarding your rights and obligations.

SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
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
// DOM-IGNORE-END

// *****************************************************************************
// *****************************************************************************
// Section: Included Files 
// *****************************************************************************
// *****************************************************************************

#include "system_config.h"
#include "system_definitions.h"
#include "driver/driver_common.h"
#include "osal/osal.h"
#include "crypto/crypto.h"
#include "system/ota/framework/csv/csv.h"

#define OTA_DEBUG   1
#define OTA_MAIN_CODE   2

#ifdef SYS_OTA_APPDEBUG_ENABLED
#define SERVICE_TYPE    OTA_DEBUG  
#else
#define SERVICE_TYPE    OTA_MAIN_CODE  
#endif




#define BOOT_ADDRESS    0xB0020000 + 0x00001000
#define APP_IMG_BOOT_CTL_BLANK      { 0xFF, 0xFF, 0xFF, 0x03, 0xFFFFFFFF,  0x00000001   ,  BOOT_ADDRESS  }
#define OTA_DOWNLOADER_TIMEOUT 1000
#define __woraround_unused_variable(x) ((void)x)

#ifdef SYS_OTA_FREE_SECTOR_CHECK_ENABLE
#define OTA_CHECK_FREE_SECTOR
#endif

typedef struct {
    FIRMWARE_IMAGE_HEADER header;
    uint8_t rsvd[4096 - sizeof (FIRMWARE_IMAGE_HEADER) - 1];
    uint8_t signature;
} OTA_BOOT_CONTROL;


const OTA_BOOT_CONTROL BOOT_CONTROL_INSTANCE\
 __attribute__((section(".ota_boot_control"))) = {\
    APP_IMG_BOOT_CTL_BLANK,
    {}, IMG_STATUS_VALID
};

typedef enum {
    OTA_TASK_INIT = 0,
    OTA_TASK_IDLE,
    OTA_TASK_ALLOCATE_SLOT,
    OTA_TASK_CHECK_DB,
    OTA_TASK_DOWNLOAD_IMAGE,
    OTA_TASK_VERIFY_IMAGE_DIGEST,
    OTA_TASK_DATABASE_ENTRY,
    OTA_TASK_SET_IMAGE_STATUS,
    OTA_TASK_FACTORY_RESET,
    OTA_TASK_ERASE_IMAGE,
    OTA_TASK_UPDATE_USER
} OTA_TASK_ID;

typedef struct {
    uint32_t slot;
    uint32_t version;
    uint8_t abort;
    uint8_t img_status;
    uint8_t pfm_status;
} OTA_TASK_PARAM;

typedef struct {

    struct {
        uint8_t context[256 + 64 + 1024];
        int state;
        OTA_TASK_PARAM param;
    } task;

    OTA_TASK_ID current_task;
    SYS_STATUS status;
    OTA_RESULT ota_result;
    OTA_COMPLETION_CALLBACK callback;
    DRV_HANDLE downloader;
    OSAL_MUTEX_HANDLE_TYPE mutex;
    bool new_downloaded_img;
    bool ota_rollback_initiated;
    bool ota_idle;
    bool db_full;
} OTA_DATA;

static OTA_DATA __attribute__((coherent, aligned(128))) ota;

static OTA_PARAMS ota_params;

extern size_t field_content_length;

#ifdef SYS_OTA_SECURE_BOOT_ENABLED
static char image_signature_file_name[100];
#endif
static bool disk_mount = false;
static uint32_t erase_ver;
static bool ota_isTls_request;
CACHE_COHERENCY ota_original_cache_policy;
#if (OTA_NVM_INT_CALLBACK_ENABLE == false)
extern bool mutex_nvm_g_status;
#endif

typedef enum {
    /* The app mounts the disk */
    APP_MOUNT_DISK = 0,

    /* The disk mount success */
    APP_MOUNT_SUCCESS,

    /* The app formats the disk. */
    APP_FORMAT_DISK,

    /* An app error has occurred */
    APP_ERROR

} APP_FILE_STATES;


uint8_t CACHE_ALIGN work[SYS_FS_FAT_MAX_SS];

typedef struct {
    /* SYS_FS File handle */
    SYS_FS_HANDLE fileHandle1;

    /*  current state */
    APP_FILE_STATES state;

    long fileSize;

} APP_DATA_FILE;
APP_DATA_FILE CACHE_ALIGN appFile;
// *****************************************************************************
// *****************************************************************************
// Section: To check if image download request is via TLS connection 
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  void OTA_IsTls_Request(const char *)

  Description:
    To check if image download request is via TLS connection 

  Task Parameters:
    Server URL
  Return:
    true - If TLS request
    false - If not a TLS connection
 */
//---------------------------------------------------------------------------
static bool OTA_IsTls_Request(const char *URIText){
    if (SYS_OTA_ENFORCE_TLS == false) {
        if (0 == strncmp(URIText, "https:", 6)) {
#if (SERVICE_TYPE == OTA_DEBUG)
        SYS_CONSOLE_PRINT("SYS OTA : TLS request\r\n");
#endif
            return true;
        } else if (0 == strncmp(URIText, "http:", 5)) {
#if (SERVICE_TYPE == OTA_DEBUG)
        SYS_CONSOLE_PRINT("SYS OTA : non-TLS request\r\n");
#endif
            return false;
        } else {
            return false;
        }
    } else {
        if (0 == strncmp(URIText, "https:", 6)) {
#if (SERVICE_TYPE == OTA_DEBUG)
        SYS_CONSOLE_PRINT("SYS OTA : TLS request\r\n");
#endif
            return true;
        } else {
            return false;
        }
    }
}
// *****************************************************************************
// *****************************************************************************
// Section:  To change cache policy 
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  void OTA_SetCachePolicy(bool)

  Description:
   To set cache policy 

  Task Parameters:
   restore_policy : true : request is for restoring  policy   
 *                  false : request is not for restoring  policy. Policy will be changed to "CACHE_WRITETHROUGH_WRITEALLOCATE"
 *                          after taking backup of current policy 
  Return:
    None
 */
//---------------------------------------------------------------------------
void OTA_SetCachePolicy(bool restore_policy){
    
    OSAL_CRITSECT_DATA_TYPE critSect;
    /* Enter the critical section.*/
    critSect = OSAL_CRIT_Enter(OSAL_CRIT_TYPE_HIGH);
    
    /*take a back up of current cache policy, this will be restored after download is completed*/
    /*Back up is to be taken only when moving from original to new. Restoring to original does not
     require back up*/
    if(restore_policy == false)
        ota_original_cache_policy = CACHE_CacheCoherencyGet();
    /*Flushing cache, after memory is synchronized */
    CACHE_CacheFlush();
    
    if(restore_policy == true){
        /*Set original cache policy after download*/
        CACHE_CacheCoherencySet(ota_original_cache_policy);
    }
    else{
        /*Set new cache policy*/
        CACHE_CacheCoherencySet(CACHE_WRITETHROUGH_WRITEALLOCATE);
    }
    
    /* Exit the critical section*/
    OSAL_CRIT_Leave(OSAL_CRIT_TYPE_HIGH, critSect);
}
// *****************************************************************************
// *****************************************************************************
// Section:  To get download status 
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  void OTA_GetDownloadStatus(OTA_PARAMS *result)

  Description:
   To get download status 

  Task Parameters:
    pointer of type ota_params 
  Return:
    None
 */
//---------------------------------------------------------------------------
void OTA_GetDownloadStatus(OTA_PARAMS *result) {
    result->server_image_length = ota_params.server_image_length;
    result->total_data_downloaded = ota_params.total_data_downloaded;
}

// *****************************************************************************
// *****************************************************************************
// Section:  To store factory image signature 
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  void OTA_StoreFactoryImageSignature(void *buf)

  Description:
   To store factory image signature

  Task Parameters:
    pointer to signature string 
  Return:
    None
 */
//---------------------------------------------------------------------------
#ifdef SYS_OTA_SECURE_BOOT_ENABLED
void OTA_StoreFactoryImageSignature(void *buf) {
    OTA_DB_ENTRY image_data;
    image_data.digest_sign = buf;
    SYS_CONSOLE_PRINT("\n\rfactory image signature : %s\n\r", image_data.digest_sign);
    //image_data.digest_sign = ota_params.serv_app_digest_sign_string;
    //strcpy(image_data.digest_sign, buf);
    strcpy(image_signature_file_name, APP_DIR_NAME);
    strcat(image_signature_file_name, "/factory_image_sign.txt");
    
    //if(ota_params.signature_verification == true){
        appFile.fileHandle1 = SYS_FS_FileOpen(image_signature_file_name, (SYS_FS_FILE_OPEN_WRITE_PLUS));
        SYS_FS_FileWrite(appFile.fileHandle1, image_data.digest_sign, strlen(image_data.digest_sign));
        SYS_FS_FileClose(appFile.fileHandle1);
    //}
}
#endif
// *****************************************************************************
// *****************************************************************************
// Section:  To get download status 
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  void OTA_GetPatchStatus(OTA_PARAMS *result)

  Description:
   To get patch progress status 

  Task Parameters:
    pointer of type ota_params 
  Return:
    None
 */
//---------------------------------------------------------------------------

// *****************************************************************************
// *****************************************************************************
// Section: Initialize required parameters for setting image status
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  void OTA_ImgStatus_Params(void)

  Description:
   Initialize required parameters for setting image status

  Task Parameters:
    None
  Return:
    None
 */
//---------------------------------------------------------------------------

void OTA_ImgStatus_Params(void) {
    /*Bootloader would have set APP_IMG_BOOT_CTL->type and APP_IMG_BOOT_CTL->version*/
    ota.task.param.version = APP_IMG_BOOT_CTL->version;
#if (SERVICE_TYPE == OTA_DEBUG)
    SYS_CONSOLE_PRINT("SYS OTA : newly uploaded image version : %d\r\n", APP_IMG_BOOT_CTL->version);
#endif
    ota.task.param.img_status = IMG_STATUS_VALID;
    ota.task.param.pfm_status = IMG_STATUS_VALID;
    ota.task.param.abort = 0;
    if (APP_IMG_BOOT_CTL->type == IMG_TYPE_FACTORY_RESET) {
        ota.current_task = OTA_TASK_UPDATE_USER;
        ota.status = SYS_STATUS_READY;
    }
}

// *****************************************************************************
// *****************************************************************************
// Section: To update user about OTA status
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  static void OTA_Task_UpdateUser(void)
  
  Description:
    To update user about OTA status
  
  Task Parameters:
    None
 
  Return:
    None
 */
//---------------------------------------------------------------------------

static void OTA_Task_UpdateUser(void) {
    OTA_COMPLETION_CALLBACK callback = ota.callback;

    /*if callback is for image download start , downloader should not be closed*/
#ifdef SYS_OTA_PATCH_ENABLE    
    if ((ota.ota_result != OTA_RESULT_IMAGE_DOWNLOAD_START) && (ota.ota_result != OTA_RESULT_PATCH_EVENT_START)) {
        if (ota.downloader != DRV_HANDLE_INVALID) {
            DOWNLOADER_Close(ota.downloader);
            ota.downloader = DRV_HANDLE_INVALID;
        }
    }
#else
    if ((ota.ota_result != OTA_RESULT_IMAGE_DOWNLOAD_START)) {
        if (ota.downloader != DRV_HANDLE_INVALID) {
            DOWNLOADER_Close(ota.downloader);
            ota.downloader = DRV_HANDLE_INVALID;
        }
    }
#endif
    ota.status = SYS_STATUS_READY;
    if (callback != NULL) {
        callback(ota.ota_result, NULL, NULL);
    }
}
// *****************************************************************************
// *****************************************************************************
// Section: Mark all downloaded image to DISABLED
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  SYS_STATUS OTA_Task_FactoryReset(void)
  
  Description:
    Mark all downloaded image to DISABLED
  
  Task Parameters:
    None
  
  Return:
    A SYS_STATUS code describing the current status.
 */
//---------------------------------------------------------------------------

typedef struct {
    uint32_t slot;

} OTA_FACTORY_RESET_TASK_CONTEXT;

typedef enum {
    TASK_STATE_F_INIT = 0,
    TASK_STATE_F_DISABLE_IMAGE,
    TASK_STATE_F_INVALIDATE_BOOT_CTL,
    TASK_STATE_F_DONE
} OTA_FACTORY_RESET_TASK_STATE;

static SYS_STATUS OTA_Task_FactoryReset(void) {


    SYS_ASSERT(sizeof (*ctx) < ota.task.context, "Buffer Overflow");

    switch (ota.task.state) {
        case TASK_STATE_F_INIT:
        {

            ota.task.state = TASK_STATE_F_DISABLE_IMAGE;
            break;
        }
        case TASK_STATE_F_DISABLE_IMAGE:
        {
#if (SERVICE_TYPE == OTA_DEBUG)
            SYS_CONSOLE_PRINT("Removing \r\n");
#endif
            SYS_FS_RESULT res = SYS_FS_RES_SUCCESS;
            if (res == SYS_FS_RES_FAILURE) {
                // Directory remove operation failed
#if (SERVICE_TYPE == OTA_DEBUG)
                SYS_CONSOLE_PRINT("SYS OTA : Directory remove operation failed\r\n");
                //while(1);
#endif
            }
            ota.task.state = TASK_STATE_F_INVALIDATE_BOOT_CTL;
            break;
        }
        case TASK_STATE_F_INVALIDATE_BOOT_CTL:
        {

            INT_Flash_Open();
            INT_Flash_Erase(APP_IMG_BOOT_CTL_WR, FLASH_SECTOR_SIZE);
            ota.task.state = TASK_STATE_F_DONE;
            break;
        }
        case TASK_STATE_F_DONE:
        {
            if (INT_Flash_Busy()) {
                break;
            }
            INT_Flash_Close();
            return SYS_STATUS_READY;
        }
        default:
        {
            SYS_ASSERT(false, "Unknown task state");
            return SYS_STATUS_ERROR;
        }
    }
    return SYS_STATUS_BUSY;
}

// *****************************************************************************
// *****************************************************************************
// Section: To register user call back function
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  _OTA_RegCB(void)
  
  Description:
    To register user call back function
  
  Task Parameters:
    None
 
  Return:
     A SYS_STATUS code describing the current status.
 */
//---------------------------------------------------------------------------

static inline SYS_STATUS _OTA_RegCB(OTA_COMPLETION_CALLBACK callback) {
    SYS_STATUS ret = SYS_STATUS_ERROR;
    if (!ota.callback) {
        /* Copy the client function pointer */
        ota.callback = callback;
        ret = SYS_STATUS_READY;
    }
    return ret;
}

// *****************************************************************************
// *****************************************************************************
// Section: To get free sector information in external disk
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  OTA_IsDisk_Full(void)
  
  Description:
    To get free sector information in external disk 
  
  Task Parameters:
    None
 
  Return:
    true - if free sector count is less than 10
    false -  if free sector count is greater than 10
 */
//---------------------------------------------------------------------------
#ifdef OTA_CHECK_FREE_SECTOR
static bool OTA_IsDisk_Full(void){
    
  uint32_t totalSectors, freeSectors;
  SYS_FS_RESULT res;  
  res = SYS_FS_DriveSectorGet(APP_DIR_NAME, &totalSectors, &freeSectors);
  if(res == SYS_FS_RES_FAILURE)
  {
        //Sector information get operation failed.
        #if (SERVICE_TYPE == OTA_DEBUG)
            SYS_CONSOLE_PRINT("SYS OTA : Sector information get operation failed\r\n");
        #endif
  }
 
  #if (SERVICE_TYPE == OTA_DEBUG)
         SYS_CONSOLE_PRINT("SYS OTA : totalSectors : %d , freeSectors : %d\n\r",totalSectors,freeSectors);
  #endif
  if(freeSectors <= 10){
      return true;
  }
  
  return false;
}
#endif
// *****************************************************************************
// *****************************************************************************
// Section: Registering OTA callback function
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  
  Description:
 Registering OTA callback function
  
  Task Parameters:
    buffer - callback function name 
    length - function pointer length
  Return:
     A SYS_STATUS code describing the current status.
 */
//---------------------------------------------------------------------------

SYS_STATUS OTA_CallBackReg(void *buffer, uint32_t length) {
    uint8_t status = SYS_STATUS_ERROR;

    OTA_COMPLETION_CALLBACK g_otaFunPtr = buffer;
    if ((g_otaFunPtr) && (length == sizeof (g_otaFunPtr))) {
        /* Register the client callback function */
        status = _OTA_RegCB(g_otaFunPtr);
    }
    return status;
}

// *****************************************************************************
// *****************************************************************************
// Section: Starting OTA process
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  SYS_STATUS OTA_Start(OTA_PARAMS *param) 
  Description:
    Starting OTA process
  
  Task Parameters:
    Parameters related to OTA, like ota url,image version etc.. 
 
  Return:
     A SYS_STATUS code describing the current status.
 */
//---------------------------------------------------------------------------

SYS_STATUS OTA_Start(OTA_PARAMS *param) {

    if (ota.current_task != OTA_TASK_IDLE) {
        return SYS_STATUS_ERROR;
    }
    
#ifdef OTA_CHECK_FREE_SECTOR
    if(OTA_IsDisk_Full() == true){
        SYS_CONSOLE_PRINT("SYS OTA : No Free Sector, Download not possible\n\r");
        return SYS_STATUS_ERROR;
    }
#endif
    ota_isTls_request = OTA_IsTls_Request(param->ota_server_url);
    ota.downloader = DOWNLOADER_Open(param->ota_server_url);
    if (ota.downloader == DRV_HANDLE_INVALID) {

        return SYS_STATUS_ERROR;
    }

    strncpy(ota_params.serv_app_digest_string, param->serv_app_digest_string, 64);
#ifdef SYS_OTA_SECURE_BOOT_ENABLED	
    ota_params.signature_verification = param->signature_verification;
    if(ota_params.signature_verification == true)
        strncpy(ota_params.serv_app_digest_sign_string, param->serv_app_digest_sign_string, 96);
#endif    
	memcpy(ota_params.ota_server_url, param->ota_server_url, strlen(param->ota_server_url) + 1);
    ota_params.version = param->version;
    ota.current_task = OTA_TASK_DOWNLOAD_IMAGE;
    
    ota.status = SYS_STATUS_BUSY;
    ota.task.param.img_status = IMG_STATUS_DOWNLOADED;
    ota.task.param.pfm_status = IMG_STATUS_DISABLED;
    ota.task.param.abort = 0;
    return SYS_STATUS_READY;
}

//---------------------------------------------------------------------------

// *****************************************************************************
// *****************************************************************************
// Section: API for upper layer to initiate Roll back
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  SYS_STATUS OTA_Rollback(void)
 
  Description:
    API for upper layer to initiate Roll back
  
  Task Parameters:
    None 
 
  Return:
     A SYS_STATUS code describing the current status.
 */
//---------------------------------------------------------------------------

SYS_STATUS OTA_Rollback(void) {
    if (ota.current_task != OTA_TASK_IDLE) {
        return SYS_STATUS_ERROR;
    }

    if (APP_IMG_BOOT_CTL->type == IMG_TYPE_FACTORY_RESET) {
        return SYS_STATUS_READY;
    }
    ota.current_task = OTA_TASK_SET_IMAGE_STATUS;
    ota.status = SYS_STATUS_BUSY;
    ota.task.param.version = APP_IMG_BOOT_CTL->version;
    ota.task.param.img_status = IMG_STATUS_DISABLED;
    ota.task.param.pfm_status = IMG_STATUS_DISABLED;
    ota.task.param.abort = 0;
    ota.ota_rollback_initiated = true;
    return SYS_STATUS_READY;
}

// *****************************************************************************
// *****************************************************************************
// Section: API for upper layer to initiate factory reset
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  SYS_STATUS OTA_FactoryReset(void) 
 
  Description:
    API for upper layer to initiate factory reset 
  
  Task Parameters:
    None 
  Return:
     A SYS_STATUS code describing the current status.
 */
//---------------------------------------------------------------------------

SYS_STATUS OTA_FactoryReset(void) {
    if (ota.current_task != OTA_TASK_IDLE) {
#if (SERVICE_TYPE == OTA_DEBUG)
        SYS_CONSOLE_PRINT("SYS OTA : Factory reset OTA task not idle : %d\r\n", ota.current_task);
#endif
        return SYS_STATUS_ERROR;
    }
    ota.current_task = OTA_TASK_FACTORY_RESET;
    ota.status = SYS_STATUS_READY;
    return SYS_STATUS_READY;
}

// *****************************************************************************
// *****************************************************************************
// Section:  API for upper layer to Erase a particular version of image
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  SYS_STATUS OTA_EraseImage(uint32_t version)
 
  Description:
    API for upper layer to Erase a particular version of image 
  
  Task Parameters:
    Image version to be erased 
 
  Return:
     A SYS_STATUS code describing the current status.
 */
//---------------------------------------------------------------------------

SYS_STATUS OTA_EraseImage(uint32_t version) {
    if (ota.current_task != OTA_TASK_IDLE) {
#if (SERVICE_TYPE == OTA_DEBUG)
        SYS_CONSOLE_PRINT("OTA not in idle : %d\r\n", ota.current_task);
#endif
        return SYS_STATUS_ERROR;
    }
    erase_ver = version;
    ota.current_task = OTA_TASK_ERASE_IMAGE;
    ota.status = SYS_STATUS_BUSY;
    return SYS_STATUS_READY;
}
// *****************************************************************************
// *****************************************************************************
// Section: To check if OTA state is idel
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  bool OTA_IsIdle(void)
 
  Description:
    To check if OTA state is idel 
  
  Task Parameters:
    None
 
  Return:
    True- if state is idle
    False- if state is not idle
 */
//---------------------------------------------------------------------------

bool OTA_IsIdle(void) {

    return ota.ota_idle;
}

// *****************************************************************************
// *****************************************************************************
// Section: To maintain OTA task state machine
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  void OTA_Tasks(void)
 
  Description:
    To maintain OTA task state machine
  
  Task Parameters:
    None
 
  Return:
    None
 */
//---------------------------------------------------------------------------

void OTA_Tasks(void) {

    switch (ota.current_task) {
        case OTA_TASK_INIT:
        {
 //SYS_OTA_FS_ENABLED
                ota.current_task = OTA_TASK_SET_IMAGE_STATUS;
                ota.task.state = OTA_TASK_INIT;
                OTA_ImgStatus_Params();
                disk_mount = false;

            break;
        }
        case OTA_TASK_SET_IMAGE_STATUS:
        {
            ota.ota_idle = false;
			ota.status = SYS_STATUS_READY;
            if (ota.status != SYS_STATUS_BUSY) {
                ota.ota_result = OTA_RESULT_NONE;
                if (ota.new_downloaded_img == true)
                    ota.ota_result = OTA_RESULT_IMAGE_STATUS_SET;
                if (ota.ota_rollback_initiated == true)
                    ota.ota_result = OTA_RESULT_ROLLBACK_DONE;
                ota.current_task = OTA_TASK_UPDATE_USER;
                ota.task.state = OTA_TASK_INIT;
#if (SERVICE_TYPE == OTA_DEBUG)
                SYS_CONSOLE_PRINT("SYS OTA : OTA_TASK_SET_IMAGE_STATUS done\r\n");
#endif
            }

            break;
        }
        case OTA_TASK_UPDATE_USER:
        {
            ota.ota_idle = false;
            ota.current_task = OTA_TASK_IDLE;
            if (ota.ota_result == OTA_RESULT_IMAGE_DOWNLOADED) {
                ota.current_task = OTA_TASK_VERIFY_IMAGE_DIGEST;
                ota.task.state = OTA_TASK_INIT;
            }
            if (ota.ota_result == OTA_RESULT_IMAGE_DIGEST_VERIFY_SUCCESS) {
                ota.current_task = OTA_TASK_DATABASE_ENTRY;
                ota.task.state = OTA_TASK_INIT;
            }
            OTA_Task_UpdateUser();
            break;
        }
        case OTA_TASK_IDLE:
        {
            ota.ota_idle = true;
            break;
        }
#if (SERVICE_TYPE == OTA_DEBUG)
        case OTA_TASK_CHECK_DB:
        {
            ota.ota_idle = false;
            ota.status = OTA_Task_DbEntryCheck();
            if (ota.status == SYS_STATUS_READY) {

                ota.current_task = OTA_TASK_DOWNLOAD_IMAGE;
                ota.task.state = OTA_TASK_INIT;
                while (1);
            }
            if (ota.status == SYS_STATUS_ERROR) {

                SYS_CONSOLE_PRINT("SYS OTA : OTA DB FULL\r\n");
                ota.current_task = OTA_TASK_UPDATE_USER;
                ota.task.state = OTA_TASK_INIT;
                while (1);
            }
            break;
        }
#endif
        case OTA_TASK_DOWNLOAD_IMAGE:
        {
            ota.ota_idle = false;
			ota.status = SYS_STATUS_READY;
            if (ota.status == SYS_STATUS_READY) {
                if(ota_isTls_request == true){
                    OTA_SetCachePolicy(true);
                }
#if (SERVICE_TYPE == OTA_DEBUG)
                SYS_CONSOLE_PRINT("SYS OTA : Downloaded image\r\n");
#endif
                ota.ota_result = OTA_RESULT_IMAGE_DOWNLOADED;
                ota.current_task = OTA_TASK_UPDATE_USER;
                ota.task.state = OTA_TASK_INIT;
                
            }

            if (ota.status == SYS_STATUS_ERROR) {
                if(ota_isTls_request == true){
                    OTA_SetCachePolicy(true);
                }
                SYS_CONSOLE_PRINT("SYS OTA : Download error\r\n");
                ota.ota_result = OTA_RESULT_IMAGE_DOWNLOAD_FAILED;
                ota.current_task = OTA_TASK_UPDATE_USER;
                ota.task.state = OTA_TASK_INIT;
            }

            break;
        }
        case OTA_TASK_VERIFY_IMAGE_DIGEST:
        {
            ota.ota_idle = false;
			ota.status = SYS_STATUS_READY;
            if (ota.status == SYS_STATUS_READY) {

#if (SERVICE_TYPE == OTA_DEBUG)
                SYS_CONSOLE_PRINT("SYS OTA : Verified image\r\n");
#endif
                ota.ota_result = OTA_RESULT_IMAGE_DIGEST_VERIFY_SUCCESS;
                ota.current_task = OTA_TASK_UPDATE_USER;
                ota.task.state = OTA_TASK_INIT;
                ota.new_downloaded_img = true;
            }

            if (ota.status == SYS_STATUS_ERROR) {
#if (SERVICE_TYPE == OTA_DEBUG)
                SYS_CONSOLE_PRINT("SYS OTA : Image verification error\r\n");
#endif
                ota.ota_result = OTA_RESULT_IMAGE_DIGEST_VERIFY_FAILED;
                ota.current_task = OTA_TASK_UPDATE_USER;
            }
            break;
        }
        case OTA_TASK_DATABASE_ENTRY:
        {
            ota.ota_idle = false;
			ota.status = SYS_STATUS_READY;
            if (ota.status == SYS_STATUS_READY) {
#if (SERVICE_TYPE == OTA_DEBUG)
                SYS_CONSOLE_PRINT("SYS OTA : Data Entered\r\n");
#endif
                ota.current_task = OTA_TASK_SET_IMAGE_STATUS;
                ota.task.state = OTA_TASK_INIT;
                
            }

            if (ota.status == SYS_STATUS_ERROR) {
#if (SERVICE_TYPE == OTA_DEBUG)
                SYS_CONSOLE_MESSAGE("SYS OTA : Database entry error\r\n");
#endif
                
                ota.ota_result = OTA_RESULT_IMAGE_DB_ENTRY_FAILED;
                ota.current_task = OTA_TASK_UPDATE_USER;
            }
            break;
        }
        case OTA_TASK_FACTORY_RESET:
        {
            ota.ota_idle = false;
#if (SERVICE_TYPE == OTA_DEBUG)
            SYS_CONSOLE_MESSAGE("SYS OTA : OTA_TASK_FACTORY_RESET\r\n");
#endif
            ota.status = OTA_Task_FactoryReset();

            if (ota.status != SYS_STATUS_BUSY) {
                ota.ota_result = OTA_RESULT_FACTORY_RESET_SUCCESS;
                ota.current_task = OTA_TASK_UPDATE_USER;
                //SYS_FS_FileClose(appFile.fileHandle);
            }
            break;
        }
        case OTA_TASK_ERASE_IMAGE:
        {
            ota.ota_idle = false;
			ota.status = SYS_STATUS_READY;
#if (SERVICE_TYPE == OTA_DEBUG)
            SYS_CONSOLE_MESSAGE("SYS OTA : OTA_TASK_ERASE_IMAGE\r\n");
#endif

            if (ota.status == SYS_STATUS_ERROR) {
                ota.ota_result = OTA_RESULT_IMAGE_ERASE_FAILED;
                ota.current_task = OTA_TASK_UPDATE_USER;
            } else {
                ota.ota_result = OTA_RESULT_IMAGE_ERASED;
                ota.current_task = OTA_TASK_UPDATE_USER;
            }
            break;
        }

        default:
        {
            break;
        }
    }
    DOWNLOADER_Tasks();
}

// *****************************************************************************
// *****************************************************************************
// Section: To Initialize OTA related parameters
// *****************************************************************************
// *****************************************************************************
//---------------------------------------------------------------------------
/*
  void OTA_Initialize(void
 
  Description:
    To Initialize OTA related parameters
  
  Task Parameters:
    None
 
  Return:
    None
 */
//---------------------------------------------------------------------------

void OTA_Initialize(void) {
    memset(&ota, 0, sizeof (ota));
    /*Initializing downloader status*/
    ota.downloader = DRV_HANDLE_INVALID;
    ota.status = SYS_STATUS_UNINITIALIZED;
    ota.current_task = OTA_TASK_INIT;
    ota.callback = NULL;
    ota.task.param.abort = 0;
    /* Registering NVM callback function */
    INT_Flash_Initialize();
    /*Initialization of Download protocol parameters*/
    DOWNLOADER_Initialize();
}
typedef struct {
    FIRMWARE_IMAGE_HEADER img;
    uint8_t *buf;
} OTA_SIGN_IMAGE_TASK_CONTEXT;

OTA_SIGN_IMAGE_TASK_CONTEXT *ctx = (void*) ota.task.context;

void OTA_UpdateBootctl() {
    ctx->buf = (uint8_t*) OSAL_Malloc(FLASH_SECTOR_SIZE);
    SYS_CONSOLE_PRINT("SYS OTA : Update boot ctrl\r\n");
    INT_Flash_Open();

    ota.task.param.img_status = IMG_STATUS_DOWNLOADED;
    ota.task.param.pfm_status = IMG_STATUS_VALID;
    ctx->img.status = IMG_STATUS_DOWNLOADED;
    ctx->img.order = 0xFF;
    ctx->img.type = IMG_TYPE_PRODUCTION;
    ctx->img.boot_addr = (0xb0000200 + (uint32_t)SYS_OTA_JUMP_TO_ADDRESS);
    INT_Flash_Erase(APP_IMG_BOOT_CTL_WR, FLASH_SECTOR_SIZE);
    memcpy(ctx->buf, &ctx->img, sizeof (FIRMWARE_IMAGE_HEADER));
    INT_Flash_Write(APP_IMG_BOOT_CTL_WR, ctx->buf, FLASH_SECTOR_SIZE);
    while( NVM_IsBusy() ) ;
    INT_Flash_Close();
    
    if (ctx->buf != NULL) {
        OSAL_Free(ctx->buf);
        ctx->buf = NULL;
    }
    SYS_OTA_SystemReset();
}
